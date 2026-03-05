# clawmoat-crewai

Security guardrails for CrewAI — protect your multi-agent crews from prompt injection, data leakage, and tool misuse.

## Install

```bash
pip install clawmoat-crewai
```

## Quick Start

```python
from crewai import Agent, Task, Crew
from clawmoat_crewai import secure_crew

# Build your crew as usual
agent = Agent(role="Researcher", goal="Find info", llm=my_llm)
task = Task(description="Research topic", agent=agent)
crew = Crew(agents=[agent], tasks=[task])

# One line to add security
secured = secure_crew(crew, block_on_critical=True)
result = secured.kickoff()
```

That's it. Every LLM call and tool use across all agents is now scanned.

## Links

- [ClawMoat](https://github.com/darfaz/clawmoat)
- [clawmoat-langchain](../langchain/) — Core LangChain integration
