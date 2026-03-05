"""ClawMoat security integration for CrewAI.

Wraps CrewAI agents and tasks with security scanning.

Usage:
    from crewai import Agent, Task, Crew
    from clawmoat_crewai import secure_crew

    crew = Crew(agents=[agent], tasks=[task])
    secured = secure_crew(crew, block_on_critical=True)
    result = secured.kickoff()
"""

from clawmoat_crewai.guard import secure_crew, SecureCrewGuard

__all__ = ["secure_crew", "SecureCrewGuard"]
__version__ = "0.1.0"
