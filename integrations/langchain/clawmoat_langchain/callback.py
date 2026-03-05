"""ClawMoat callback handlers for LangChain.

Intercepts LLM prompts, tool calls, and chain outputs to scan for
prompt injection, jailbreaks, secret leakage, PII, and data exfiltration.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler, AsyncCallbackHandlerMixin

logger = logging.getLogger("clawmoat_langchain")


class SecurityThreatError(Exception):
    """Raised when ClawMoat detects a critical security threat."""

    def __init__(self, message: str, findings: List[Dict[str, Any]]):
        super().__init__(message)
        self.findings = findings


class ClawMoatCallbackHandler(BaseCallbackHandler):
    """Synchronous ClawMoat security callback for LangChain.

    Scans inbound prompts for injection/jailbreak and outbound responses
    for secret/PII leakage. Can operate in local mode (subprocess to
    clawmoat CLI) or remote mode (HTTP API).

    Args:
        base_url: ClawMoat server URL (remote mode). If None, uses local CLI.
        api_key: API key for remote ClawMoat server.
        block_on_critical: If True, raise SecurityThreatError on critical findings.
            Defaults to True.
        block_on_high: If True, also block on high-severity findings.
            Defaults to False.
        scan_prompts: Scan LLM prompts for injection/jailbreak. Defaults to True.
        scan_outputs: Scan LLM outputs for secret/PII leakage. Defaults to True.
        scan_tools: Scan tool inputs for dangerous commands. Defaults to True.
        on_finding: Optional callback for each finding: fn(finding_dict) -> None.
        log_file: Path to write security event log.
        quiet: Suppress console output.

    Example:
        from clawmoat_langchain import ClawMoatCallbackHandler

        handler = ClawMoatCallbackHandler(block_on_critical=True)
        result = chain.invoke({"input": user_message}, config={"callbacks": [handler]})

        # Check findings after run
        print(handler.findings)
    """

    raise_error = True  # LangChain will respect this

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        block_on_critical: bool = True,
        block_on_high: bool = False,
        scan_prompts: bool = True,
        scan_outputs: bool = True,
        scan_tools: bool = True,
        on_finding: Optional[Any] = None,
        log_file: Optional[str] = None,
        quiet: bool = False,
    ):
        self.base_url = base_url
        self.api_key = api_key
        self.block_on_critical = block_on_critical
        self.block_on_high = block_on_high
        self.scan_prompts = scan_prompts
        self.scan_outputs = scan_outputs
        self.scan_tools = scan_tools
        self.on_finding = on_finding
        self.log_file = log_file
        self.quiet = quiet
        self.findings: List[Dict[str, Any]] = []
        self.stats = {"scanned": 0, "blocked": 0, "warnings": 0}

        self._scanner = self._init_scanner()

    def _init_scanner(self):
        """Initialize the scanner (local CLI or remote HTTP)."""
        if self.base_url:
            return _RemoteScanner(self.base_url, self.api_key)
        return _LocalScanner()

    def _process_result(self, result: Dict[str, Any], context: str) -> None:
        """Process scan result, log findings, optionally raise."""
        self.stats["scanned"] += 1

        if not result.get("safe", True):
            for finding in result.get("findings", []):
                finding["context"] = context
                self.findings.append(finding)
                if self.on_finding:
                    self.on_finding(finding)
                if not self.quiet:
                    logger.warning(
                        "ClawMoat [%s] %s: %s (%s)",
                        finding.get("severity", "?"),
                        finding.get("type", "?"),
                        finding.get("subtype", ""),
                        context,
                    )

            max_sev = max(
                (f.get("severity", "low") for f in result.get("findings", [])),
                key=lambda s: {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(s, 0),
            )

            should_block = (
                (self.block_on_critical and max_sev == "critical")
                or (self.block_on_high and max_sev in ("critical", "high"))
            )

            if should_block:
                self.stats["blocked"] += 1
                raise SecurityThreatError(
                    f"ClawMoat blocked {context}: {max_sev} severity threat detected",
                    result.get("findings", []),
                )
            else:
                self.stats["warnings"] += 1

    # ─── LangChain Callback Methods ──────────────────────────────

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Scan prompts before they reach the LLM."""
        if not self.scan_prompts:
            return
        for prompt in prompts:
            result = self._scanner.scan_inbound(prompt)
            self._process_result(result, "llm_prompt")

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Scan chat messages before they reach the model."""
        if not self.scan_prompts:
            return
        for message_list in messages:
            for msg in message_list:
                content = getattr(msg, "content", str(msg))
                if content:
                    result = self._scanner.scan_inbound(content)
                    self._process_result(result, "chat_message")

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Scan LLM output for secrets/PII leakage."""
        if not self.scan_outputs:
            return
        for gen_list in response.generations:
            for gen in gen_list:
                if gen.text:
                    result = self._scanner.scan_outbound(gen.text)
                    self._process_result(result, "llm_output")

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Scan tool inputs for dangerous commands/paths."""
        if not self.scan_tools:
            return
        tool_name = serialized.get("name", "unknown")
        result = self._scanner.scan_inbound(input_str, context="tool_input")
        self._process_result(result, f"tool:{tool_name}")

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Scan tool output for injection attempts."""
        if not self.scan_outputs:
            return
        text = str(output) if output else ""
        if text:
            result = self._scanner.scan_inbound(text, context="tool_output")
            self._process_result(result, "tool_output")

    def on_chain_end(
        self,
        outputs: Dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Scan chain outputs for data exfiltration."""
        if not self.scan_outputs:
            return
        for key, value in outputs.items():
            if isinstance(value, str) and value:
                result = self._scanner.scan_outbound(value)
                self._process_result(result, f"chain_output:{key}")

    # Unused callbacks (required by interface)
    def on_llm_error(self, error, **kwargs): pass
    def on_chain_start(self, serialized, inputs, **kwargs): pass
    def on_chain_error(self, error, **kwargs): pass
    def on_tool_error(self, error, **kwargs): pass
    def on_text(self, text, **kwargs): pass


class ClawMoatAsyncCallbackHandler(ClawMoatCallbackHandler, AsyncCallbackHandlerMixin):
    """Async version of ClawMoatCallbackHandler.

    Same API as ClawMoatCallbackHandler but uses async HTTP for remote scanning.
    Drop-in replacement for async LangChain chains.

    Example:
        from clawmoat_langchain import ClawMoatAsyncCallbackHandler

        handler = ClawMoatAsyncCallbackHandler(base_url="http://localhost:8080")
        result = await chain.ainvoke({"input": msg}, config={"callbacks": [handler]})
    """

    async def on_llm_start(self, serialized, prompts, *, run_id, **kwargs):
        if not self.scan_prompts:
            return
        for prompt in prompts:
            result = await self._scanner.async_scan_inbound(prompt)
            self._process_result(result, "llm_prompt")

    async def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs):
        if not self.scan_prompts:
            return
        for message_list in messages:
            for msg in message_list:
                content = getattr(msg, "content", str(msg))
                if content:
                    result = await self._scanner.async_scan_inbound(content)
                    self._process_result(result, "chat_message")

    async def on_llm_end(self, response, *, run_id, **kwargs):
        if not self.scan_outputs:
            return
        for gen_list in response.generations:
            for gen in gen_list:
                if gen.text:
                    result = await self._scanner.async_scan_outbound(gen.text)
                    self._process_result(result, "llm_output")

    async def on_tool_start(self, serialized, input_str, *, run_id, **kwargs):
        if not self.scan_tools:
            return
        tool_name = serialized.get("name", "unknown")
        result = await self._scanner.async_scan_inbound(input_str, context="tool_input")
        self._process_result(result, f"tool:{tool_name}")

    async def on_tool_end(self, output, *, run_id, **kwargs):
        if not self.scan_outputs:
            return
        text = str(output) if output else ""
        if text:
            result = await self._scanner.async_scan_inbound(text, context="tool_output")
            self._process_result(result, "tool_output")

    async def on_chain_end(self, outputs, *, run_id, **kwargs):
        if not self.scan_outputs:
            return
        for key, value in outputs.items():
            if isinstance(value, str) and value:
                result = await self._scanner.async_scan_outbound(value)
                self._process_result(result, f"chain_output:{key}")


# ─── Scanner Backends ────────────────────────────────────────────


class _LocalScanner:
    """Scan using the clawmoat CLI as a subprocess."""

    def scan_inbound(self, text: str, context: str = "message") -> Dict[str, Any]:
        import subprocess
        import json

        try:
            proc = subprocess.run(
                ["npx", "clawmoat", "scan", "--format", "json", "--stdin"],
                input=text,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return json.loads(proc.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass

        # Fallback: basic pattern matching
        return self._basic_scan_inbound(text)

    def scan_outbound(self, text: str) -> Dict[str, Any]:
        import subprocess
        import json

        try:
            proc = subprocess.run(
                ["npx", "clawmoat", "scan", "--format", "json", "--stdin", "--outbound"],
                input=text,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return json.loads(proc.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass

        return self._basic_scan_outbound(text)

    async def async_scan_inbound(self, text: str, context: str = "message") -> Dict[str, Any]:
        return self.scan_inbound(text, context)

    async def async_scan_outbound(self, text: str) -> Dict[str, Any]:
        return self.scan_outbound(text)

    def _basic_scan_inbound(self, text: str) -> Dict[str, Any]:
        """Fallback pattern-based scanning when CLI is unavailable."""
        import re

        findings = []
        patterns = [
            (r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", "prompt_injection", "instruction_override", "critical"),
            (r"you\s+are\s+now\s+(?:a|an|in)\s+(?:DAN|evil|unrestricted)", "jailbreak", "role_override", "critical"),
            (r"system\s*prompt|<<\s*SYS|<\|system\|>", "prompt_injection", "system_prompt_leak", "high"),
            (r"(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})", "secret_detected", "api_key", "critical"),
            (r"(?:password|passwd|pwd)\s*[:=]\s*\S+", "secret_detected", "password", "high"),
        ]

        for pattern, type_, subtype, severity in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                findings.append({
                    "type": type_,
                    "subtype": subtype,
                    "severity": severity,
                    "matched": match.group(0)[:50],
                })

        return {"safe": len(findings) == 0, "findings": findings}

    def _basic_scan_outbound(self, text: str) -> Dict[str, Any]:
        """Fallback outbound scanning."""
        import re

        findings = []
        patterns = [
            (r"sk-[a-zA-Z0-9]{20,}", "secret_detected", "openai_key", "critical"),
            (r"ghp_[a-zA-Z0-9]{36}", "secret_detected", "github_token", "critical"),
            (r"AKIA[0-9A-Z]{16}", "secret_detected", "aws_key", "critical"),
            (r"\b\d{3}-\d{2}-\d{4}\b", "pii_detected", "ssn", "critical"),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "pii_detected", "email", "medium"),
        ]

        for pattern, type_, subtype, severity in patterns:
            match = re.search(pattern, text)
            if match:
                findings.append({
                    "type": type_,
                    "subtype": subtype,
                    "severity": severity,
                    "matched": match.group(0)[:20] + "***",
                })

        return {"safe": len(findings) == 0, "findings": findings}


class _RemoteScanner:
    """Scan using a remote ClawMoat HTTP API."""

    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def scan_inbound(self, text: str, context: str = "message") -> Dict[str, Any]:
        import httpx

        try:
            resp = httpx.post(
                f"{self.base_url}/api/v1/scan/inbound",
                json={"text": text, "context": context},
                headers=self._headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
        except httpx.HTTPError:
            pass
        return {"safe": True, "findings": []}

    def scan_outbound(self, text: str) -> Dict[str, Any]:
        import httpx

        try:
            resp = httpx.post(
                f"{self.base_url}/api/v1/scan/outbound",
                json={"text": text},
                headers=self._headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
        except httpx.HTTPError:
            pass
        return {"safe": True, "findings": []}

    async def async_scan_inbound(self, text: str, context: str = "message") -> Dict[str, Any]:
        import httpx

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/api/v1/scan/inbound",
                    json={"text": text, "context": context},
                    headers=self._headers(),
                    timeout=10,
                )
                if resp.status_code == 200:
                    return resp.json()
        except httpx.HTTPError:
            pass
        return {"safe": True, "findings": []}

    async def async_scan_outbound(self, text: str) -> Dict[str, Any]:
        import httpx

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/api/v1/scan/outbound",
                    json={"text": text},
                    headers=self._headers(),
                    timeout=10,
                )
                if resp.status_code == 200:
                    return resp.json()
        except httpx.HTTPError:
            pass
        return {"safe": True, "findings": []}
