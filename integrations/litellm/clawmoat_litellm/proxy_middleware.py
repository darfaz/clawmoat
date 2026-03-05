"""LiteLLM proxy middleware for ClawMoat security scanning."""

from typing import Dict, Any, List, Optional
import json
import time


class ClawMoatProxyMiddleware:
    """Middleware for LiteLLM proxy server to add ClawMoat security scanning.
    
    This can be used in LiteLLM proxy deployments to add security scanning
    at the gateway level without modifying client applications.
    """
    
    def __init__(
        self,
        clawmoat_config: Optional[Dict[str, Any]] = None,
        block_on_critical: bool = True,
        log_all_requests: bool = True
    ):
        """Initialize proxy middleware.
        
        Args:
            clawmoat_config: Configuration for ClawMoat scanning
            block_on_critical: Whether to block on critical threats
            log_all_requests: Whether to log all requests for audit
        """
        self.clawmoat_config = clawmoat_config or {}
        self.block_on_critical = block_on_critical
        self.log_all_requests = log_all_requests
        
        # Import ClawMoat callback for actual scanning
        try:
            from .callback import ClawMoatCallback
            self.scanner = ClawMoatCallback(
                block_on_critical=block_on_critical,
                **self.clawmoat_config
            )
        except ImportError as e:
            print(f"Warning: Could not initialize ClawMoat scanner: {e}")
            self.scanner = None
            
        self.request_log = []

    def pre_call_hook(self, user_id: str, model: str, messages: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Called before each LLM API call.
        
        Returns:
            Dict with any modifications or metadata to attach
        """
        request_id = f"req_{int(time.time() * 1000)}"
        
        request_info = {
            "request_id": request_id,
            "timestamp": time.time(),
            "user_id": user_id,
            "model": model,
            "message_count": len(messages),
            "status": "processing"
        }
        
        if self.log_all_requests:
            self.request_log.append(request_info)
            
        # Perform security scanning if scanner is available
        if self.scanner:
            try:
                self.scanner.log_pre_api_call(model, messages, kwargs)
                request_info["security_scan"] = "passed"
            except ValueError as e:
                # ClawMoat blocked the request
                request_info["security_scan"] = "blocked"
                request_info["block_reason"] = str(e)
                request_info["status"] = "blocked"
                
                # Re-raise to block the request
                raise e
            except Exception as e:
                # Scanning error - log but don't block (depending on fallback mode)
                request_info["security_scan"] = "error"
                request_info["scan_error"] = str(e)
                
                # Continue unless configured to block on errors
                if self.scanner.fallback_mode == "block":
                    raise ValueError(f"Security scanning failed: {e}")
        
        # Return metadata to attach to this request
        return {
            "clawmoat_request_id": request_id,
            "clawmoat_scan_status": request_info.get("security_scan", "skipped")
        }

    def post_call_hook(
        self,
        user_id: str,
        model: str,
        response: Any,
        request_metadata: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """Called after successful LLM API call.
        
        Args:
            user_id: User identifier
            model: Model name used
            response: LLM response object
            request_metadata: Metadata from pre_call_hook
            
        Returns:
            Dict with response metadata
        """
        request_id = request_metadata.get("clawmoat_request_id")
        
        # Update request log
        if self.log_all_requests and request_id:
            for req in self.request_log:
                if req.get("request_id") == request_id:
                    req["status"] = "completed"
                    req["completion_time"] = time.time()
                    req["duration_ms"] = (req["completion_time"] - req["timestamp"]) * 1000
                    break
        
        # Perform output scanning if scanner is available
        scan_results = {}
        if self.scanner:
            try:
                from datetime import datetime
                start_time = datetime.fromtimestamp(time.time())
                end_time = datetime.fromtimestamp(time.time())
                
                self.scanner.log_success_event(kwargs, response, start_time, end_time)
                scan_results["output_scan"] = "completed"
                scan_results["findings_count"] = len(self.scanner.findings)
                
            except Exception as e:
                scan_results["output_scan"] = "error"
                scan_results["scan_error"] = str(e)
        
        return {
            "clawmoat_output_scan": scan_results,
            "clawmoat_total_findings": len(self.scanner.findings) if self.scanner else 0
        }

    def error_hook(
        self,
        user_id: str,
        model: str,
        error: Exception,
        request_metadata: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """Called when LLM API call fails."""
        request_id = request_metadata.get("clawmoat_request_id")
        
        # Update request log
        if self.log_all_requests and request_id:
            for req in self.request_log:
                if req.get("request_id") == request_id:
                    req["status"] = "error"
                    req["error"] = str(error)
                    req["completion_time"] = time.time()
                    req["duration_ms"] = (req["completion_time"] - req["timestamp"]) * 1000
                    break
        
        return {
            "clawmoat_error_logged": True
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive stats about requests and security scanning."""
        if not self.log_all_requests:
            return {"error": "Request logging is disabled"}
            
        total_requests = len(self.request_log)
        completed = len([r for r in self.request_log if r["status"] == "completed"])
        blocked = len([r for r in self.request_log if r["status"] == "blocked"])
        errors = len([r for r in self.request_log if r["status"] == "error"])
        
        stats = {
            "total_requests": total_requests,
            "completed": completed,
            "blocked": blocked,
            "errors": errors,
            "block_rate": blocked / total_requests if total_requests > 0 else 0,
            "success_rate": completed / total_requests if total_requests > 0 else 0
        }
        
        # Add scanner stats if available
        if self.scanner:
            stats.update(self.scanner.stats)
            
        return stats

    def get_recent_blocks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent blocked requests for audit."""
        blocked_requests = [
            r for r in self.request_log 
            if r["status"] == "blocked"
        ]
        
        # Sort by timestamp, most recent first
        blocked_requests.sort(key=lambda r: r["timestamp"], reverse=True)
        
        return blocked_requests[:limit]

    def get_security_findings(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent security findings from scanner."""
        if not self.scanner:
            return []
            
        # Return most recent findings
        return self.scanner.findings[-limit:] if self.scanner.findings else []
        
    def clear_logs(self) -> None:
        """Clear request logs and findings (for testing/maintenance)."""
        self.request_log.clear()
        if self.scanner:
            self.scanner.findings.clear()
            self.scanner.stats = {
                "requests_scanned": 0,
                "threats_detected": 0,
                "requests_blocked": 0,
                "fallbacks": 0
            }