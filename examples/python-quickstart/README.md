# ClawMoat Python Quickstart

ClawMoat is a Node.js package. This quickstart shows how to use it from Python agents.

## Prerequisites

```bash
npm install -g clawmoat
```

## Usage

```python
from clawmoat_client import ClawMoat, ClawMoatError

moat = ClawMoat()

# Scan tool results before passing to your agent
result = moat.scan_inbound(tool_output)
if not result["safe"]:
    raise Exception(f"Blocked: {result['findings'][0]['type']}")

# Or use assert_safe (raises ClawMoatError automatically)
moat.assert_safe(tool_output)

# Scan model output before returning to user
moat.assert_safe(model_response, direction="outbound")
```

## LangChain Integration

```python
from clawmoat_client import ClawMoatCallbackHandler

agent = initialize_agent(
    tools=tools,
    llm=llm,
    callbacks=[ClawMoatCallbackHandler()]  # scans all tool outputs automatically
)
```

## What it catches

- Prompt injection in retrieved content (indirect injection)
- Secret/credential exfiltration in outputs  
- Jailbreak attempts
- Dangerous command patterns
- Supply chain attacks in dependencies

## Run the example

```bash
python clawmoat_client.py
```
