"""CrewAI security guard using ClawMoat.

Hooks into CrewAI's callback/step system to scan agent actions.
Uses the same scanner backend as clawmoat-langchain.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from clawmoat_langchain.callback import ClawMoatCallbackHandler, SecurityThreatError

logger = logging.getLogger("clawmoat_crewai")


class SecureCrewGuard:
    """Security wrapper for CrewAI crews.

    Injects ClawMoat callback handlers into all agents in a crew,
    providing runtime security scanning for every LLM call and tool use.

    Args:
        block_on_critical: Block execution on critical threats. Default True.
        block_on_high: Also block on high-severity. Default False.
        base_url: Remote ClawMoat server URL (optional).
        api_key: API key for remote server (optional).
        on_finding: Callback for each security finding.
    """

    def __init__(
        self,
        block_on_critical: bool = True,
        block_on_high: bool = False,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        on_finding: Optional[Any] = None,
    ):
        self.handler = ClawMoatCallbackHandler(
            base_url=base_url,
            api_key=api_key,
            block_on_critical=block_on_critical,
            block_on_high=block_on_high,
            on_finding=on_finding,
        )

    def secure(self, crew: Any) -> Any:
        """Add ClawMoat security to all agents in a CrewAI crew.

        Modifies agents in-place to include the security callback handler.
        Returns the crew for chaining.
        """
        for agent in crew.agents:
            if hasattr(agent, 'llm') and agent.llm:
                existing = getattr(agent.llm, 'callbacks', None) or []
                if self.handler not in existing:
                    existing.append(self.handler)
                    agent.llm.callbacks = existing

            # Also hook into agent-level callbacks if available
            if hasattr(agent, 'callbacks'):
                if agent.callbacks is None:
                    agent.callbacks = []
                if self.handler not in agent.callbacks:
                    agent.callbacks.append(self.handler)

        logger.info("ClawMoat: Secured %d agents in crew", len(crew.agents))
        return crew

    @property
    def findings(self) -> List[Dict[str, Any]]:
        return self.handler.findings

    @property
    def stats(self) -> Dict[str, int]:
        return self.handler.stats


def secure_crew(
    crew: Any,
    block_on_critical: bool = True,
    block_on_high: bool = False,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    on_finding: Optional[Any] = None,
) -> Any:
    """Convenience function to add ClawMoat security to a CrewAI crew.

    Usage:
        from clawmoat_crewai import secure_crew

        crew = Crew(agents=[agent], tasks=[task])
        secured = secure_crew(crew)
        result = secured.kickoff()
    """
    guard = SecureCrewGuard(
        block_on_critical=block_on_critical,
        block_on_high=block_on_high,
        base_url=base_url,
        api_key=api_key,
        on_finding=on_finding,
    )
    return guard.secure(crew)
