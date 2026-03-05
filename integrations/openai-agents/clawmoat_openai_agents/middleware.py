"""OpenAI Agents SDK middleware for ClawMoat security scanning."""

from typing import Dict, Any, List, Optional, AsyncGenerator, Union
import json
import time


class ClawMoatAgentMiddleware:
    """Middleware for OpenAI Agents SDK to add comprehensive ClawMoat security.
    
    This provides a higher-level integration that can wrap entire agents
    or conversation flows with security scanning and policy enforcement.
    """
    
    def __init__(
        self,
        guardrail_config: Optional[Dict[str, Any]] = None,
        enable_conversation_tracking: bool = True,
        max_conversation_length: int = 50,
        audit_all_interactions: bool = True
    ):
        """Initialize ClawMoat agent middleware.
        
        Args:
            guardrail_config: Configuration for ClawMoat guardrails
            enable_conversation_tracking: Track conversation history for context
            max_conversation_length: Maximum turns to keep in conversation history
            audit_all_interactions: Whether to audit all agent interactions
        """
        self.guardrail_config = guardrail_config or {}
        self.enable_conversation_tracking = enable_conversation_tracking
        self.max_conversation_length = max_conversation_length
        self.audit_all_interactions = audit_all_interactions
        
        # Initialize guardrails
        try:
            from .guardrail import ClawMoatGuardrail
            self.input_guardrail = ClawMoatGuardrail(
                scan_input=True,
                scan_output=False,
                **self.guardrail_config
            )
            self.output_guardrail = ClawMoatGuardrail(
                scan_input=False,
                scan_output=True,
                **self.guardrail_config
            )
        except ImportError as e:
            print(f"Warning: Could not initialize ClawMoat guardrails: {e}")
            self.input_guardrail = None
            self.output_guardrail = None
            
        # State tracking
        self.conversation_history = []
        self.interaction_log = []
        self.security_summary = {
            "total_interactions": 0,
            "blocked_inputs": 0,
            "blocked_outputs": 0,
            "threats_detected": 0,
            "last_threat": None
        }

    def wrap_agent(self, agent):
        """Wrap an OpenAI agent with ClawMoat security middleware.
        
        Returns a new agent instance with security guardrails attached.
        """
        try:
            # Add ClawMoat guardrails to the agent
            if hasattr(agent, 'input_guardrails') and self.input_guardrail:
                if not agent.input_guardrails:
                    agent.input_guardrails = []
                agent.input_guardrails.append(self.input_guardrail)
                
            if hasattr(agent, 'output_guardrails') and self.output_guardrail:
                if not agent.output_guardrails:
                    agent.output_guardrails = []
                agent.output_guardrails.append(self.output_guardrail)
                
            # Wrap key methods for additional tracking
            original_run = agent.run if hasattr(agent, 'run') else None
            if original_run:
                agent.run = self._wrap_run_method(original_run)
                
            return agent
            
        except Exception as e:
            print(f"Warning: Could not fully wrap agent with ClawMoat: {e}")
            return agent

    def _wrap_run_method(self, original_run):
        """Wrap the agent's run method to add security tracking."""
        def wrapped_run(*args, **kwargs):
            interaction_id = f"interaction_{int(time.time() * 1000)}"
            start_time = time.time()
            
            # Pre-run security check
            try:
                self.security_summary["total_interactions"] += 1
                
                # Log interaction start
                if self.audit_all_interactions:
                    self.interaction_log.append({
                        "id": interaction_id,
                        "timestamp": start_time,
                        "type": "agent_run_start",
                        "args_count": len(args),
                        "kwargs_keys": list(kwargs.keys()) if kwargs else []
                    })
                
                # Call original run method
                result = original_run(*args, **kwargs)
                
                # Post-run processing
                end_time = time.time()
                duration = end_time - start_time
                
                if self.audit_all_interactions:
                    self.interaction_log.append({
                        "id": interaction_id,
                        "timestamp": end_time,
                        "type": "agent_run_complete",
                        "duration": duration,
                        "success": True
                    })
                
                # Update conversation tracking
                if self.enable_conversation_tracking:
                    self._update_conversation_tracking(args, kwargs, result)
                
                return result
                
            except Exception as e:
                # Handle errors
                end_time = time.time()
                duration = end_time - start_time
                
                if self.audit_all_interactions:
                    self.interaction_log.append({
                        "id": interaction_id,
                        "timestamp": end_time,
                        "type": "agent_run_error",
                        "duration": duration,
                        "error": str(e),
                        "success": False
                    })
                
                # Check if this was a security block
                if "ClawMoat" in str(e) or "blocked" in str(e).lower():
                    self.security_summary["blocked_inputs"] += 1
                    self.security_summary["last_threat"] = {
                        "timestamp": end_time,
                        "type": "input_blocked",
                        "error": str(e)
                    }
                
                # Re-raise the original exception
                raise
        
        return wrapped_run

    def _update_conversation_tracking(self, args, kwargs, result):
        """Update conversation history tracking."""
        try:
            # Extract conversation turn from args/kwargs
            turn_data = {
                "timestamp": time.time(),
                "input": self._extract_input_content(args, kwargs),
                "output": self._extract_output_content(result),
            }
            
            # Add to conversation history
            self.conversation_history.append(turn_data)
            
            # Trim history if too long
            if len(self.conversation_history) > self.max_conversation_length:
                self.conversation_history = self.conversation_history[-self.max_conversation_length:]
                
        except Exception as e:
            # Don't fail the main operation if tracking fails
            if self.guardrail_config.get("verbose", False):
                print(f"Conversation tracking error: {e}")

    def _extract_input_content(self, args, kwargs) -> str:
        """Extract input content for conversation tracking."""
        content_parts = []
        
        # Extract from args
        for arg in args:
            if isinstance(arg, str):
                content_parts.append(arg)
            elif hasattr(arg, 'content'):
                content_parts.append(str(arg.content))
            elif isinstance(arg, dict):
                if 'content' in arg:
                    content_parts.append(str(arg['content']))
                elif 'message' in arg:
                    content_parts.append(str(arg['message']))
        
        # Extract from kwargs
        for key, value in kwargs.items():
            if key in ['message', 'prompt', 'input', 'content']:
                content_parts.append(str(value))
                
        return " ".join(content_parts)

    def _extract_output_content(self, result) -> str:
        """Extract output content for conversation tracking."""
        try:
            if isinstance(result, str):
                return result
            elif hasattr(result, 'content'):
                return str(result.content)
            elif hasattr(result, 'message'):
                return str(result.message)
            elif isinstance(result, dict):
                if 'content' in result:
                    return str(result['content'])
                elif 'message' in result:
                    return str(result['message'])
                elif 'response' in result:
                    return str(result['response'])
            return str(result)
        except Exception:
            return "[Unable to extract content]"

    def get_security_summary(self) -> Dict[str, Any]:
        """Get comprehensive security summary."""
        summary = {
            **self.security_summary,
            "conversation_length": len(self.conversation_history),
            "total_interactions_logged": len(self.interaction_log),
        }
        
        # Add guardrail stats if available
        if self.input_guardrail:
            summary["input_stats"] = self.input_guardrail.get_stats()
        if self.output_guardrail:
            summary["output_stats"] = self.output_guardrail.get_stats()
            
        return summary

    def get_conversation_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent conversation history."""
        return self.conversation_history[-limit:] if self.conversation_history else []

    def get_recent_interactions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent interaction logs."""
        return self.interaction_log[-limit:] if self.interaction_log else []

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of detected threats."""
        all_findings = []
        
        if self.input_guardrail:
            all_findings.extend(self.input_guardrail.findings)
        if self.output_guardrail:
            all_findings.extend(self.output_guardrail.findings)
            
        # Group by threat type
        threat_counts = {}
        for finding in all_findings:
            threat_type = finding.get("type", "unknown")
            severity = finding.get("severity", "unknown")
            key = f"{threat_type}_{severity}"
            threat_counts[key] = threat_counts.get(key, 0) + 1
            
        return {
            "total_threats": len(all_findings),
            "threat_breakdown": threat_counts,
            "recent_threats": all_findings[-5:] if all_findings else [],
            "last_threat_time": self.security_summary.get("last_threat", {}).get("timestamp")
        }

    def export_audit_log(self, format: str = "json") -> str:
        """Export complete audit log for compliance."""
        audit_data = {
            "metadata": {
                "export_timestamp": time.time(),
                "total_interactions": len(self.interaction_log),
                "conversation_turns": len(self.conversation_history),
                "security_summary": self.security_summary
            },
            "interactions": self.interaction_log,
            "conversation_history": self.conversation_history if self.enable_conversation_tracking else [],
            "threat_summary": self.get_threat_summary(),
            "security_stats": self.get_security_summary()
        }
        
        if format.lower() == "json":
            return json.dumps(audit_data, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def reset_tracking(self) -> None:
        """Reset all tracking data (for testing or cleanup)."""
        self.conversation_history.clear()
        self.interaction_log.clear()
        self.security_summary = {
            "total_interactions": 0,
            "blocked_inputs": 0,
            "blocked_outputs": 0,
            "threats_detected": 0,
            "last_threat": None
        }
        
        if self.input_guardrail:
            self.input_guardrail.reset_stats()
        if self.output_guardrail:
            self.output_guardrail.reset_stats()