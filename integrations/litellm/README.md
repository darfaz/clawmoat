# clawmoat-litellm

Security scanning middleware for LiteLLM proxy — transparent protection for all models and providers without application changes.

## Install

```bash
pip install clawmoat-litellm
```

## Quick Start

### Option 1: LiteLLM Config File

Add to your `litellm_config.yaml`:

```yaml
model_list:
  - model_name: gpt-4
    provider: openai
  - model_name: claude-3
    provider: anthropic

litellm_settings:
  callbacks: ["clawmoat_litellm.ClawMoatCallback"]
  
general_settings:
  # ClawMoat configuration
  clawmoat:
    block_on_critical: true
    block_on_high: false
    scan_input: true
    scan_output: true
    base_url: "http://localhost:8080"  # Optional: ClawMoat server
```

### Option 2: Programmatic Setup

```python
import litellm
from clawmoat_litellm import ClawMoatCallback

# Add ClawMoat as a callback
litellm.callbacks = [ClawMoatCallback(block_on_critical=True)]

# Now all LLM calls are protected
response = litellm.completion(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

### Option 3: Proxy Deployment

```python
from litellm import proxy
from clawmoat_litellm import ClawMoatProxyMiddleware

# Add security middleware to proxy
middleware = ClawMoatProxyMiddleware(
    block_on_critical=True,
    log_all_requests=True
)

# Register hooks
proxy.register_pre_call_hook(middleware.pre_call_hook)
proxy.register_post_call_hook(middleware.post_call_hook)
```

## What It Protects

| Attack Vector | Detection | Action |
|---------------|-----------|--------|
| **Prompt Injection** | Pattern matching, intent analysis | Block or log |
| **Jailbreak Attempts** | Known attack signatures | Block or log |
| **PII/Secrets in Input** | Regex + ML patterns | Block or redact |
| **Data Exfiltration** | Output scanning for credentials | Log and optionally redact |
| **Excessive Agency** | Privilege escalation patterns | Block |

## Configuration

### ClawMoat Server Mode

For full scanning capabilities, run a ClawMoat server:

```bash
# Start ClawMoat server
clawmoat serve --port 8080

# Configure LiteLLM to use it
litellm.callbacks = [ClawMoatCallback(
    base_url="http://localhost:8080",
    api_key="your-api-key"
)]
```

### Local Mode

For lightweight scanning without external dependencies:

```python
callback = ClawMoatCallback(
    base_url=None,  # Use local scanning
    block_on_critical=True
)
```

### Advanced Configuration

```python
callback = ClawMoatCallback(
    # Security settings
    block_on_critical=True,
    block_on_high=False,
    scan_input=True,
    scan_output=True,
    
    # Performance settings  
    timeout=5,                    # API timeout seconds
    fallback_mode="allow",        # "allow" | "block" on errors
    
    # Remote server (optional)
    base_url="http://localhost:8080",
    api_key="sk-clawmoat-...",
    
    # Debugging
    verbose=True
)
```

## Monitoring & Stats

```python
# Access scanning statistics
print(callback.stats)
# {
#   "requests_scanned": 156,
#   "threats_detected": 3,
#   "requests_blocked": 1,
#   "fallbacks": 0
# }

# View detected threats
for finding in callback.findings:
    print(f"{finding['type']}: {finding['description']}")
    
# For proxy middleware
middleware = ClawMoatProxyMiddleware()
print(middleware.get_stats())
print(middleware.get_recent_blocks(limit=5))
```

## Enterprise Features

### Audit Logging

All security events are logged for compliance:

```python
callback = ClawMoatCallback(
    base_url="http://your-clawmoat-server.com",
    verbose=True  # Enables audit logging
)

# Logs include:
# - Request/response content (configurable)
# - Security findings and severity
# - Block/allow decisions
# - User identifiers and timestamps
```

### Custom Policies

Define organization-specific security policies:

```yaml
# clawmoat_policy.yaml
policies:
  - name: "block_competitor_research" 
    pattern: ".*competitor.*financial.*data.*"
    action: "block"
    severity: "high"
    
  - name: "redact_customer_pii"
    pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"  # SSN
    action: "redact"
    replacement: "[SSN_REDACTED]"
```

### Multi-Tenant Support

```python
# Different policies per user/tenant
callback = ClawMoatCallback(
    policy_selector=lambda user_id: f"policies/{user_id}.yaml"
)
```

## Integration Examples

### FastAPI + LiteLLM

```python
from fastapi import FastAPI
import litellm
from clawmoat_litellm import ClawMoatCallback

app = FastAPI()

# Configure security
litellm.callbacks = [ClawMoatCallback(block_on_critical=True)]

@app.post("/chat")
async def chat_endpoint(message: str):
    try:
        response = litellm.completion(
            model="gpt-4",
            messages=[{"role": "user", "content": message}]
        )
        return {"response": response.choices[0].message.content}
    except ValueError as e:
        # ClawMoat blocked the request
        return {"error": "Request blocked by security system", "reason": str(e)}, 403
```

### LangChain via LiteLLM

```python
from langchain_community.llms import LiteLLM
from clawmoat_litellm import ClawMoatCallback

# Add security to LangChain via LiteLLM
litellm.callbacks = [ClawMoatCallback()]

llm = LiteLLM(model="gpt-4")
response = llm("What is the capital of France?")  # Protected automatically
```

### Kubernetes Deployment

```yaml
# k8s-litellm-clawmoat.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: litellm-proxy-secure
spec:
  template:
    spec:
      containers:
      - name: litellm
        image: ghcr.io/berriai/litellm:main-latest
        env:
        - name: LITELLM_MASTER_KEY
          value: "sk-1234"
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
      volumes:
      - name: config
        configMap:
          name: litellm-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: litellm-config
data:
  config.yaml: |
    model_list:
      - model_name: gpt-4
        provider: openai
    litellm_settings:
      callbacks: ["clawmoat_litellm.ClawMoatCallback"]
    general_settings:
      clawmoat:
        block_on_critical: true
        base_url: "http://clawmoat-service:8080"
```

## Performance

- **Latency Impact:** ~10-50ms per request (local mode) / ~20-100ms (server mode)
- **Memory Usage:** ~5-20MB additional depending on findings cache size
- **Throughput:** Negligible impact on proxy throughput
- **Scaling:** Each callback instance maintains independent state

## Troubleshooting

### Common Issues

**ClawMoat server unreachable:**
```python
callback = ClawMoatCallback(
    base_url="http://localhost:8080",
    fallback_mode="allow",  # Don't block when server is down
    timeout=2              # Shorter timeout
)
```

**Too many false positives:**
```python
callback = ClawMoatCallback(
    block_on_critical=True,
    block_on_high=False,    # Only block critical threats
    verbose=True           # See what's being detected
)
```

**Performance concerns:**
```python
callback = ClawMoatCallback(
    scan_input=True,
    scan_output=False,     # Skip output scanning for speed
    timeout=1             # Aggressive timeout
)
```

## Links

- [ClawMoat](https://github.com/darfaz/clawmoat) — Open-source runtime security for AI agents
- [LiteLLM](https://github.com/BerriAI/litellm) — Universal LLM proxy
- [clawmoat-langchain](../langchain/) — Direct LangChain integration