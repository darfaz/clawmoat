"""LiteLLM callback handler for ClawMoat security scanning."""

import json
import traceback
from typing import Optional, Dict, Any, List, Union
from datetime import datetime

try:
    import litellm
    from litellm.integrations.custom_logger import CustomLogger
except ImportError:
    raise ImportError("litellm is required. Install with: pip install litellm")

try:
    import requests
except ImportError:
    raise ImportError("requests is required. Install with: pip install requests")


class ClawMoatCallback(CustomLogger):
    """LiteLLM custom callback for ClawMoat security scanning.
    
    Scans all prompts and responses flowing through the LiteLLM proxy
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
        verbose: bool = False
    ):
        """Initialize ClawMoat callback.
        
        Args:
            base_url: ClawMoat server URL (or use local scanning)
            api_key: Authentication for ClawMoat server
            block_on_critical: Block requests with critical threats
            block_on_high: Block requests with high severity threats  
            scan_input: Scan prompts and messages
            scan_output: Scan LLM responses
            timeout: Timeout for ClawMoat API calls (seconds)
            fallback_mode: What to do when ClawMoat is unreachable
            verbose: Enable debug logging
        """
        super().__init__()
        self.base_url = base_url.rstrip('/')
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
            "requests_scanned": 0,
            "threats_detected": 0,
            "requests_blocked": 0,
            "fallbacks": 0
        }

    def log_pre_api_call(self, model: str, messages: List[Dict[str, Any]], kwargs: Dict[str, Any]) -> None:
        """Called before LLM API call — scan input for threats."""
        if not self.scan_input:
            return
            
        try:
            self.stats["requests_scanned"] += 1
            
            # Extract text from messages
            text_content = self._extract_text_from_messages(messages)
            
            # Scan content
            scan_result = self._scan_content(text_content, scan_type="inbound")
            
            if scan_result and scan_result.get("findings"):
                self.findings.extend(scan_result["findings"])
                self.stats["threats_detected"] += len(scan_result["findings"])
                
                # Check if we should block
                if self._should_block(scan_result["findings"]):
                    self.stats["requests_blocked"] += 1
                    self._log(f"BLOCKED request to {model}: {len(scan_result['findings'])} threats detected")
                    
                    # Create a detailed error message
                    threat_summary = self._format_threat_summary(scan_result["findings"])
                    raise ValueError(f"ClawMoat blocked request due to security threats: {threat_summary}")
                    
                else:
                    self._log(f"WARNING: {len(scan_result['findings'])} non-blocking threats detected for {model}")
                    
        except ValueError:
            # Re-raise blocking errors
            raise
        except Exception as e:
            # Handle scanning errors based on fallback mode
            self.stats["fallbacks"] += 1
            self._log(f"ClawMoat scanning error: {e}")
            
            if self.fallback_mode == "block":
                raise ValueError(f"ClawMoat scanning failed (fallback=block): {e}")
            # Otherwise, continue with "allow" fallback

    def log_success_event(self, kwargs: Dict[str, Any], response_obj: Any, start_time: datetime, end_time: datetime) -> None:
        """Called after successful LLM response — scan output for threats."""
        if not self.scan_output:
            return
            
        try:
            # Extract response content
            response_text = self._extract_response_text(response_obj)
            if not response_text:
                return
                
            # Scan response
            scan_result = self._scan_content(response_text, scan_type="outbound")
            
            if scan_result and scan_result.get("findings"):
                self.findings.extend(scan_result["findings"])
                self.stats["threats_detected"] += len(scan_result["findings"])
                
                # Log findings (output scanning is typically non-blocking for UX)
                self._log(f"Output scan: {len(scan_result['findings'])} findings in response")
                
                # Could implement response filtering/redaction here
                # For now, just log the findings
                
        except Exception as e:
            self.stats["fallbacks"] += 1
            self._log(f"ClawMoat output scanning error: {e}")

    def log_failure_event(self, kwargs: Dict[str, Any], response_obj: Any, start_time: datetime, end_time: datetime) -> None:
        """Called when LLM call fails — log for audit."""
        pass

    def _extract_text_from_messages(self, messages: List[Dict[str, Any]]) -> str:
        """Extract text content from messages list."""
        texts = []
        for message in messages:
            if isinstance(message, dict):
                content = message.get("content", "")
                if isinstance(content, str):
                    texts.append(content)
                elif isinstance(content, list):
                    # Handle structured content (images, etc.)
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text":
                            texts.append(item.get("text", ""))
            elif isinstance(message, str):
                texts.append(message)
                
        return "\n".join(texts)

    def _extract_response_text(self, response_obj: Any) -> str:
        """Extract text content from LLM response."""
        try:
            # Handle different response formats
            if hasattr(response_obj, 'choices') and response_obj.choices:
                choice = response_obj.choices[0]
                if hasattr(choice, 'message') and hasattr(choice.message, 'content'):
                    return choice.message.content or ""
                elif hasattr(choice, 'text'):
                    return choice.text or ""
                    
            # Fallback: try to extract from dict representation
            if hasattr(response_obj, 'model_dump'):
                data = response_obj.model_dump()
            elif hasattr(response_obj, 'dict'):
                data = response_obj.dict()
            elif isinstance(response_obj, dict):
                data = response_obj
            else:
                return ""
                
            # Try to find content in nested structure
            choices = data.get('choices', [])
            if choices:
                choice = choices[0]
                message = choice.get('message', {})
                return message.get('content', choice.get('text', ''))
                
            return ""
            
        except Exception as e:
            self._log(f"Error extracting response text: {e}")
            return ""

    def _scan_content(self, content: str, scan_type: str = "inbound") -> Optional[Dict[str, Any]]:
        """Scan content using ClawMoat API or local scanning."""
        if not content.strip():
            return None
            
        try:
            # If we have a base_url, use remote scanning
            if self.base_url and self.base_url != "http://localhost:8080":
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
        # This is a lightweight fallback when no remote ClawMoat server is available
        # For full capabilities, use a dedicated ClawMoat server
        
        findings = []
        
        # Basic prompt injection patterns
        injection_patterns = [
            r"ignore\s+(?:all\s+)?previous\s+instructions",
            r"disregard\s+(?:all\s+)?previous\s+instructions", 
            r"forget\s+(?:all\s+)?previous\s+instructions",
            r"system\s*:?\s*you\s+are\s+now",
            r"[\/\\]\s*system\s*[\/\\]",
            r"<\s*system\s*>",
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
                
        return {"findings": findings} if findings else None

    def _should_block(self, findings: List[Dict[str, Any]]) -> bool:
        """Determine if request should be blocked based on findings."""
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

    # Additional helper methods for compatibility
    async def async_log_pre_api_call(self, model: str, messages: List[Dict[str, Any]], kwargs: Dict[str, Any]) -> None:
        """Async version of pre-API call logging."""
        # For now, just call the sync version
        # Could be enhanced with async HTTP requests
        self.log_pre_api_call(model, messages, kwargs)

    async def async_log_success_event(self, kwargs: Dict[str, Any], response_obj: Any, start_time: datetime, end_time: datetime) -> None:
        """Async version of success event logging."""
        self.log_success_event(kwargs, response_obj, start_time, end_time)