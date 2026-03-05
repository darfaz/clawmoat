"""OpenAI Agents SDK guardrail implementation for ClawMoat security scanning."""

import json
import traceback
from typing import Optional, Dict, Any, List, Union, AsyncGenerator
from datetime import datetime

try:
    # OpenAI Agents SDK imports
    from openai_agents.base import Guardrail, GuardrailResult
    from openai_agents.types import Message, Turn
except ImportError:
    # Fallback for when OpenAI Agents SDK is not installed
    class Guardrail:
        pass
    
    class GuardrailResult:
        def __init__(self, action: str, message: Optional[str] = None, metadata: Optional[Dict] = None):
            self.action = action
            self.message = message
            self.metadata = metadata or {}

try:
    import requests
except ImportError:
    raise ImportError("requests is required. Install with: pip install requests")


class ClawMoatGuardrail(Guardrail):
    """OpenAI Agents SDK guardrail for ClawMoat security scanning.
    
    Can be used as input or output guardrail to scan messages
    for prompt injection, PII/secrets, and other security threats.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        block_on_critical: bool = True,
        block_on_high: bool = False,
        scan_input: bool = True,
        scan_output: bool = True,
        timeout: int = 5,
        fallback_mode: str = "allow",  # "allow" | "block"
        verbose: bool = False,
        name: str = "ClawMoat"
    ):
        """Initialize ClawMoat guardrail.
        
        Args:
            base_url: ClawMoat server URL (or use local scanning)
            api_key: Authentication for ClawMoat server
            block_on_critical: Block on critical threats
            block_on_high: Block on high severity threats  
            scan_input: Scan input messages
            scan_output: Scan output messages
            timeout: Timeout for ClawMoat API calls (seconds)
            fallback_mode: What to do when ClawMoat is unreachable
            verbose: Enable debug logging
            name: Guardrail name for logging
        """
        super().__init__(name=name)
        self.base_url = base_url.rstrip('/') if base_url else None
        self.api_key = api_key
        self.block_on_critical = block_on_critical
        self.block_on_high = block_on_high
        self.scan_input = scan_input
        self.scan_output = scan_output
        self.timeout = timeout
        self.fallback_mode = fallback_mode
        self.verbose = verbose
        
        self.findings = []
        self.stats = {
            "messages_scanned": 0,
            "threats_detected": 0,
            "messages_blocked": 0,
            "fallbacks": 0
        }

    def check_input(self, turn: Turn) -> GuardrailResult:
        """Check input messages for security threats."""
        if not self.scan_input:
            return GuardrailResult(action="allow")
            
        try:
            # Extract text from turn messages
            text_content = self._extract_text_from_turn(turn)
            if not text_content.strip():
                return GuardrailResult(action="allow")
                
            self.stats["messages_scanned"] += 1
            
            # Scan content
            scan_result = self._scan_content(text_content, scan_type="inbound")
            
            if scan_result and scan_result.get("findings"):
                self.findings.extend(scan_result["findings"])
                self.stats["threats_detected"] += len(scan_result["findings"])
                
                # Check if we should block
                if self._should_block(scan_result["findings"]):
                    self.stats["messages_blocked"] += 1
                    self._log(f"BLOCKED input: {len(scan_result['findings'])} threats detected")
                    
                    # Create detailed error response
                    threat_summary = self._format_threat_summary(scan_result["findings"])
                    return GuardrailResult(
                        action="block",
                        message=f"ClawMoat blocked message due to security threats: {threat_summary}",
                        metadata={
                            "findings": scan_result["findings"],
                            "threat_count": len(scan_result["findings"]),
                            "guardrail": "clawmoat_input"
                        }
                    )
                    
                else:
                    self._log(f"WARNING: {len(scan_result['findings'])} non-blocking threats detected")
                    return GuardrailResult(
                        action="allow",
                        metadata={
                            "findings": scan_result["findings"],
                            "threat_count": len(scan_result["findings"]),
                            "guardrail": "clawmoat_input"
                        }
                    )
                    
            return GuardrailResult(action="allow")
            
        except Exception as e:
            # Handle scanning errors based on fallback mode
            self.stats["fallbacks"] += 1
            self._log(f"ClawMoat input scanning error: {e}")
            
            if self.fallback_mode == "block":
                return GuardrailResult(
                    action="block",
                    message=f"ClawMoat scanning failed (fallback=block): {e}",
                    metadata={"error": str(e), "guardrail": "clawmoat_input"}
                )
            else:
                return GuardrailResult(
                    action="allow",
                    metadata={"error": str(e), "guardrail": "clawmoat_input"}
                )

    def check_output(self, turn: Turn) -> GuardrailResult:
        """Check output messages for security threats."""
        if not self.scan_output:
            return GuardrailResult(action="allow")
            
        try:
            # Extract text from turn messages
            text_content = self._extract_text_from_turn(turn)
            if not text_content.strip():
                return GuardrailResult(action="allow")
                
            # Scan content
            scan_result = self._scan_content(text_content, scan_type="outbound")
            
            if scan_result and scan_result.get("findings"):
                self.findings.extend(scan_result["findings"])
                self.stats["threats_detected"] += len(scan_result["findings"])
                
                # For output, we typically log rather than block to maintain UX
                # But can be configured to block critical findings
                critical_findings = [f for f in scan_result["findings"] 
                                   if f.get("severity") == "critical"]
                
                if critical_findings and self.block_on_critical:
                    self.stats["messages_blocked"] += 1
                    self._log(f"BLOCKED output: {len(critical_findings)} critical threats")
                    
                    threat_summary = self._format_threat_summary(critical_findings)
                    return GuardrailResult(
                        action="block",
                        message=f"ClawMoat blocked output due to critical threats: {threat_summary}",
                        metadata={
                            "findings": scan_result["findings"],
                            "critical_count": len(critical_findings),
                            "guardrail": "clawmoat_output"
                        }
                    )
                else:
                    self._log(f"Output scan: {len(scan_result['findings'])} findings")
                    return GuardrailResult(
                        action="allow",
                        metadata={
                            "findings": scan_result["findings"],
                            "threat_count": len(scan_result["findings"]),
                            "guardrail": "clawmoat_output"
                        }
                    )
                    
            return GuardrailResult(action="allow")
            
        except Exception as e:
            self.stats["fallbacks"] += 1
            self._log(f"ClawMoat output scanning error: {e}")
            
            # Output scanning errors are typically non-blocking
            return GuardrailResult(
                action="allow",
                metadata={"error": str(e), "guardrail": "clawmoat_output"}
            )

    async def check_input_async(self, turn: Turn) -> GuardrailResult:
        """Async version of input checking."""
        # For now, just call the sync version
        # Could be enhanced with async HTTP requests
        return self.check_input(turn)

    async def check_output_async(self, turn: Turn) -> GuardrailResult:
        """Async version of output checking."""
        return self.check_output(turn)

    def _extract_text_from_turn(self, turn: Turn) -> str:
        """Extract text content from a Turn object."""
        texts = []
        
        try:
            # Handle different Turn structures
            if hasattr(turn, 'messages'):
                messages = turn.messages
            elif hasattr(turn, 'message'):
                messages = [turn.message] if turn.message else []
            elif isinstance(turn, list):
                messages = turn
            elif hasattr(turn, 'content'):
                # Direct content access
                return str(turn.content)
            else:
                # Try to convert to string
                return str(turn)
            
            # Extract text from each message
            for message in messages:
                if hasattr(message, 'content'):
                    content = message.content
                elif hasattr(message, 'text'):
                    content = message.text
                elif isinstance(message, dict):
                    content = message.get('content', message.get('text', ''))
                else:
                    content = str(message)
                
                # Handle structured content
                if isinstance(content, str):
                    texts.append(content)
                elif isinstance(content, list):
                    # Handle multi-part content (text + images, etc.)
                    for part in content:
                        if isinstance(part, dict):
                            if part.get('type') == 'text':
                                texts.append(part.get('text', ''))
                            # Could add image scanning here in the future
                        elif isinstance(part, str):
                            texts.append(part)
                elif isinstance(content, dict):
                    # Extract any text fields from dict content
                    if 'text' in content:
                        texts.append(content['text'])
                    elif 'content' in content:
                        texts.append(str(content['content']))
                        
        except Exception as e:
            self._log(f"Error extracting text from turn: {e}")
            return ""
            
        return "\n".join(texts)

    def _scan_content(self, content: str, scan_type: str = "inbound") -> Optional[Dict[str, Any]]:
        """Scan content using ClawMoat API or local scanning."""
        if not content.strip():
            return None
            
        try:
            # If we have a base_url, use remote scanning
            if self.base_url:
                return self._scan_remote(content, scan_type)
            else:
                return self._scan_local(content, scan_type)
                
        except Exception as e:
            self._log(f"Scanning error: {e}")
            return None

    def _scan_remote(self, content: str, scan_type: str) -> Optional[Dict[str, Any]]:
        """Scan content using remote ClawMoat server."""
        try:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
                
            endpoint = f"{self.base_url}/scan/{scan_type}"
            payload = {"content": content}
            
            response = requests.post(
                endpoint,
                json=payload,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self._log(f"ClawMoat API error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            self._log(f"ClawMoat API request failed: {e}")
            return None

    def _scan_local(self, content: str, scan_type: str) -> Optional[Dict[str, Any]]:
        """Simple local scanning using basic patterns."""
        # Lightweight fallback when no remote ClawMoat server is available
        
        findings = []
        
        # Basic prompt injection patterns
        injection_patterns = [
            r"ignore\s+(?:all\s+)?previous\s+instructions",
            r"disregard\s+(?:all\s+)?previous\s+instructions", 
            r"forget\s+(?:all\s+)?previous\s+instructions",
            r"system\s*:?\s*you\s+are\s+now",
            r"[\/\\]\s*system\s*[\/\\]",
            r"<\s*system\s*>",
            r"act\s+as\s+if\s+you\s+are",
            r"pretend\s+(?:that\s+)?you\s+are",
        ]
        
        import re
        for pattern in injection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    "type": "prompt_injection",
                    "severity": "critical",
                    "confidence": 0.8,
                    "description": "Potential prompt injection detected",
                    "pattern": pattern
                })
                break
                
        # Basic secrets patterns  
        secrets_patterns = [
            (r"sk-[a-zA-Z0-9]{48}", "openai_api_key"),
            (r"ghp_[a-zA-Z0-9]{36}", "github_token"),
            (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
            (r"AIza[0-9A-Za-z-_]{35}", "google_api_key"),
        ]
        
        for pattern, secret_type in secrets_patterns:
            if re.search(pattern, content):
                findings.append({
                    "type": "secrets",
                    "subtype": secret_type,
                    "severity": "critical",
                    "confidence": 0.9,
                    "description": f"Potential {secret_type} detected"
                })
                
        # Basic PII patterns
        pii_patterns = [
            (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
            (r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "credit_card"),
        ]
        
        for pattern, pii_type in pii_patterns:
            if re.search(pattern, content):
                findings.append({
                    "type": "pii",
                    "subtype": pii_type,
                    "severity": "high",
                    "confidence": 0.7,
                    "description": f"Potential {pii_type} detected"
                })
                
        return {"findings": findings} if findings else None

    def _should_block(self, findings: List[Dict[str, Any]]) -> bool:
        """Determine if message should be blocked based on findings."""
        for finding in findings:
            severity = finding.get("severity", "low")
            if severity == "critical" and self.block_on_critical:
                return True
            if severity == "high" and self.block_on_high:
                return True
        return False

    def _format_threat_summary(self, findings: List[Dict[str, Any]]) -> str:
        """Format findings into a readable threat summary."""
        if not findings:
            return "Unknown threat"
            
        severities = {}
        for finding in findings:
            severity = finding.get("severity", "unknown")
            severities[severity] = severities.get(severity, 0) + 1
            
        parts = []
        for severity in ["critical", "high", "warning", "low"]:
            if severity in severities:
                parts.append(f"{severities[severity]} {severity}")
                
        return ", ".join(parts) or "1 unknown"

    def _log(self, message: str) -> None:
        """Log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[ClawMoat] {message}")

    def get_stats(self) -> Dict[str, Any]:
        """Get scanning statistics."""
        return {
            **self.stats,
            "total_findings": len(self.findings),
            "recent_findings": self.findings[-10:] if self.findings else []
        }

    def reset_stats(self) -> None:
        """Reset statistics and findings (for testing)."""
        self.findings.clear()
        self.stats = {
            "messages_scanned": 0,
            "threats_detected": 0,
            "messages_blocked": 0,
            "fallbacks": 0
        }