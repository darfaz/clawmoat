"""ClawMoat security integration for OpenAI Agents SDK.

Provides guardrails for the OpenAI Agents framework to detect
prompt injection, data exfiltration, and other security threats.

Usage:
    from openai_agents import Agent
    from clawmoat_openai_agents import ClawMoatGuardrail
    
    agent = Agent(
        input_guardrails=[ClawMoatGuardrail()],
        output_guardrails=[ClawMoatGuardrail()]
    )
"""

from clawmoat_openai_agents.guardrail import ClawMoatGuardrail
from clawmoat_openai_agents.middleware import ClawMoatAgentMiddleware

__all__ = ["ClawMoatGuardrail", "ClawMoatAgentMiddleware"]
__version__ = "0.1.0"