# RFC: Defense-in-Depth for AI Agents — ClawMoat × Agent-OS Collaboration

**Status:** Draft  
**Author(s):** ClawMoat Team, Agent-OS/AgentMesh Team  
**Date:** March 2026  
**Version:** 1.0  

## Abstract

AI agents operate with real-world tool access (shell, files, APIs, browsers) and require robust security architecture. This RFC proposes a **defense-in-depth** approach combining ClawMoat's reactive security scanning with Agent-OS's proactive governance layer. Together, they provide comprehensive protection against the OWASP Agentic Top 10 threats while maintaining agent functionality and developer experience.

---

## 1. Problem Statement

### Current Landscape Fragmentation

The AI agent security landscape is fragmented with each framework implementing their own (or no) security model:

- **LangChain:** Basic output parsers, limited input validation
- **CrewAI:** Framework-level role restrictions, no runtime scanning
- **AutoGen:** Conversation-level safety filters, limited tool governance
- **OpenAI Agents SDK:** Output-focused guardrails, minimal input protection
- **Google Agent Development Kit:** Enterprise features, vendor lock-in
- **PydanticAI:** Type safety focus, limited security scanning

### Security Gaps

**Single-layer approaches fail:**
- Input-only filtering misses dynamic threats
- Output-only scanning allows malicious tool execution
- Framework-specific security doesn't protect cross-framework deployments
- Policy engines without scanning miss sophisticated attacks

**No single security layer is sufficient** — sophisticated threats require multiple coordinated defenses.

---

## 2. Defense-in-Depth Architecture

### Layer 1: Perimeter (ClawMoat)

**Role:** Reactive threat detection and content scanning  
**Scope:** Input/output analysis, prompt injection detection, data exfiltration prevention

**Components:**
- **Input Scanners:** Prompt injection, jailbreak attempts, excessive agency requests
- **Output Scanners:** PII/secrets leakage, unauthorized data sharing, policy violations  
- **Tool Scanners:** Command validation, file access monitoring, network egress logging
- **Behavioral Analysis:** Insider threat patterns, anomaly detection

**Coverage:**
- OWASP Agentic A01: Prompt Injection
- OWASP Agentic A02: Insecure Output Handling  
- OWASP Agentic A03: Training Data Poisoning (detection)
- OWASP Agentic A06: Excessive Agency
- OWASP Agentic A09: Misinformation (patterns)
- OWASP Agentic A10: Unbounded Consumption

### Layer 2: Governance (Agent-OS)

**Role:** Proactive policy enforcement and action interception  
**Scope:** Permission models, approval workflows, action authorization

**Components:**
- **Policy Engine:** YAML-based rules, role-based permissions, conditional access
- **Action Interceptor:** Pre-execution validation, approval workflows, audit trails
- **Trust System:** 5-dimension scoring, behavior-based reputation, temporal decay
- **Audit Chain:** Tamper-evident Merkle tree, compliance reporting, forensics

**Coverage:**
- OWASP Agentic A04: Model Denial of Service (rate limiting)
- OWASP Agentic A05: Supply Chain Vulnerabilities (tool validation)
- OWASP Agentic A06: Excessive Agency (authorization)
- OWASP Agentic A07: System Prompt Leakage (access control)
- OWASP Agentic A08: Vector and Embeddings Weaknesses (data governance)

### Layer 3: Runtime (Framework)

**Role:** Framework-specific guardrails and tool-level access control  
**Scope:** Native integrations, performance optimization, developer experience

**Components:**
- **LangChain:** Custom callback handlers, memory protection, chain validation
- **CrewAI:** Role-based tool restrictions, task validation, crew permissions  
- **OpenAI Agents SDK:** Guardrail protocol implementation, handoff security
- **AutoGen:** Conversation filtering, agent isolation, group chat moderation

### Layer 4: Audit

**Role:** Comprehensive logging, alerting, and compliance reporting  
**Scope:** Cross-layer visibility, threat intelligence, regulatory compliance

**Components:**
- **Unified Logging:** JSONL format, structured events, searchable metadata
- **Threat Intelligence:** IOCs, attack patterns, behavioral baselines
- **Compliance Engine:** SOX, PCI-DSS, HIPAA reporting, audit trails
- **Alerting:** Real-time notifications, escalation workflows, incident response

---

## 3. Integration Points

### 3.1 Pre-Execution Pipeline

```
User Input → ClawMoat Scan → Agent-OS Policy → Framework Guards → Tool Execution
```

**Flow:**
1. **ClawMoat** scans input for prompt injection, malicious content
2. **Agent-OS** evaluates against governance policies, role permissions  
3. **Framework** applies native guardrails, tool restrictions
4. **Tool** executes with monitoring and logging

**Benefits:**
- Threats caught at perimeter before reaching agent
- Policy violations blocked before execution
- Multiple validation layers prevent bypass

### 3.2 Post-Execution Pipeline

```
Tool Output → ClawMoat Scan → Agent-OS Audit → Framework Response → User
```

**Flow:**
1. **Tool** generates output, ClawMoat scans for PII/secrets
2. **Agent-OS** records action outcome, updates trust score
3. **Framework** applies output formatting, response validation
4. **User** receives sanitized, policy-compliant response

**Benefits:**
- Data exfiltration prevented at multiple checkpoints
- Behavioral patterns recorded for anomaly detection
- Compliance requirements automatically enforced

### 3.3 Shared Policy Format

**Unified YAML schema** for cross-platform compatibility:

```yaml
# clawmoat-agentmesh-policy.yml
metadata:
  version: "1.0"
  frameworks: ["langchain", "crewai", "openai-agents"]
  
clawmoat:
  scanners:
    prompt_injection: { enabled: true, threshold: 0.8 }
    secrets: { enabled: true, redact: true }
    pii: { enabled: true, anonymize: ["ssn", "credit_card"] }
  
agentmesh:
  permissions:
    tools:
      - name: "web_search" 
        allow: ["research_agent"]
        rate_limit: { calls: 10, window: "1m" }
      - name: "file_write"
        allow: ["admin_agent"]
        approval_required: true
  trust:
    min_score: 0.7
    factors: ["tool_success", "policy_compliance", "user_feedback"]

frameworks:
  langchain:
    callbacks: ["clawmoat_scanner", "agentmesh_governor"]
    memory_protection: true
  crewai:
    middleware: ["security_layer"]
    role_inheritance: false
```

### 3.4 Common Threat Taxonomy

**Mapped to OWASP Agentic Top 10** for consistent threat classification:

| OWASP ID | Threat | ClawMoat Detection | Agent-OS Mitigation | Framework Guard |
|----------|--------|-------------------|-------------------|-----------------|
| A01 | Prompt Injection | Input scanning, pattern matching | Policy validation, role checks | Conversation filtering |
| A02 | Insecure Output | PII/secret detection, data classification | Output approval, redaction policies | Response validation |
| A06 | Excessive Agency | Privilege escalation detection | Permission enforcement, approval | Tool restrictions |
| A09 | Misinformation | Content validation, fact-checking | Source verification, trust scoring | Output disclaimers |

---

## 4. Framework Support Matrix

### 4.1 LangChain Integration

**ClawMoat Integration:**
```python
from clawmoat.integrations.langchain import ClawMoatCallback

chain = LLMChain(
    llm=OpenAI(),
    callbacks=[ClawMoatCallback(
        scan_input=True,
        scan_output=True,
        block_threats=True
    )]
)
```

**Agent-OS Integration:**
```python
from agentmesh.integrations.langchain import AgentMeshGovernor

governor = AgentMeshGovernor(policy_path="policy.yml")
chain = governor.wrap(chain)  # Adds policy enforcement
```

### 4.2 CrewAI Integration

**Combined Middleware:**
```python
from clawmoat.integrations.crewai import ClawMoatMiddleware
from agentmesh.integrations.crewai import AgentMeshMiddleware

crew = Crew(
    agents=[researcher, writer],
    middleware=[
        ClawMoatMiddleware(),      # Threat scanning
        AgentMeshMiddleware()      # Policy enforcement
    ]
)
```

### 4.3 OpenAI Agents SDK Integration

**Guardrail Chaining:**
```python
from clawmoat.integrations.openai_agents import ClawMoatGuardrail
from agentmesh.integrations.openai_agents import AgentMeshGuardrail

agent = Agent(
    input_guardrails=[
        ClawMoatGuardrail(),      # Scan before processing
        AgentMeshGuardrail()      # Enforce permissions
    ]
)
```

---

## 5. Reference Implementation

### 5.1 CrewAI Security Stack

**Complete defense-in-depth for CrewAI:**

```python
from crewai import Agent, Task, Crew
from clawmoat.integrations.crewai import ClawMoatMiddleware
from agentmesh.integrations.crewai import AgentMeshMiddleware

# Layer 1: ClawMoat scanning
security_scanner = ClawMoatMiddleware(
    scan_input=True,
    scan_output=True, 
    scan_tools=True,
    block_on_threat=True
)

# Layer 2: Agent-OS governance  
governance = AgentMeshMiddleware(
    policy_path="security-policy.yml",
    approval_required=["file_write", "network_request"],
    trust_threshold=0.7
)

# Layer 3: Framework guards
research_agent = Agent(
    role="Security Researcher",
    goal="Research threats safely",
    tools=[web_search, file_read],  # Restricted toolset
    max_rpm=10,                     # Rate limiting
    memory=False                    # No persistent memory
)

# Combined protection
crew = Crew(
    agents=[research_agent],
    middleware=[security_scanner, governance],
    verbose=True
)

result = crew.kickoff(task="Research AI security best practices")
```

### 5.2 Policy Configuration

**Unified security policy:**

```yaml
# security-policy.yml
metadata:
  name: "AI Agent Security Policy"
  version: "1.0"
  scope: ["research", "analysis"] 
  
clawmoat:
  input_scanning:
    prompt_injection: { enabled: true, threshold: 0.8, action: "block" }
    jailbreak: { enabled: true, action: "log_and_continue" }
    excessive_agency: { enabled: true, threshold: 0.9, action: "block" }
    
  output_scanning:
    pii: { enabled: true, types: ["ssn", "credit_card"], action: "redact" }
    secrets: { enabled: true, action: "block" }
    
  tool_monitoring:
    file_access: { log: true, forbidden_paths: ["~/.ssh", "/etc/passwd"] }
    network: { log: true, blocked_domains: ["malware.com"] }
    
agentmesh:
  roles:
    research_agent:
      tools: ["web_search", "file_read"]
      rate_limits: { web_search: "10/min", file_read: "50/min" }
      approval: { required: false, escalate_on_block: true }
      
    admin_agent:
      tools: ["web_search", "file_read", "file_write", "shell_exec"]
      rate_limits: { shell_exec: "5/hour" }
      approval: { required: true, approvers: ["security_team"] }
      
  trust_system:
    enabled: true
    min_score: 0.6
    factors:
      - name: "compliance" 
        weight: 0.4
        decay: "7d"
      - name: "tool_success"
        weight: 0.3  
        decay: "3d"
      - name: "user_feedback"
        weight: 0.3
        decay: "30d"
```

---

## 6. Benefits and Trade-offs

### 6.1 Benefits

**Security:**
- **Comprehensive Coverage:** Multiple detection mechanisms prevent single-point failures
- **Threat Intelligence Sharing:** Cross-layer visibility improves detection accuracy
- **Zero-Day Protection:** Behavioral analysis catches novel attack patterns
- **Compliance Ready:** Built-in audit trails and reporting

**Developer Experience:**
- **Framework Agnostic:** Works with any agent framework
- **Gradual Adoption:** Can implement layers incrementally  
- **Policy as Code:** Version-controlled, reviewable security configuration
- **Minimal Performance Impact:** Optimized scanning and caching

**Operations:**
- **Unified Dashboards:** Single pane of glass for security monitoring
- **Automated Response:** Policy violations trigger automatic remediation
- **Forensics:** Complete audit trail for incident investigation
- **Scaling:** Distributed architecture supports large agent deployments

### 6.2 Trade-offs

**Performance:**
- **Latency:** Each layer adds processing overhead (~50-100ms total)
- **Resource Usage:** Scanning and governance require CPU/memory
- **Throughput:** Rate limiting may reduce peak agent performance

**Complexity:**
- **Configuration:** More moving parts require careful setup
- **Debugging:** Multi-layer failures harder to diagnose
- **Updates:** Changes require coordination across components

**False Positives:**
- **Over-blocking:** Conservative policies may impact legitimate use cases
- **Tuning Required:** Thresholds need adjustment for specific domains
- **Context Loss:** Cross-layer decisions may lack full context

### 6.3 Mitigation Strategies

**Performance:**
- Asynchronous scanning where possible
- Caching of policy decisions and threat signatures
- Optional bypass modes for trusted environments

**Complexity:**
- Unified configuration format reduces mental overhead
- Comprehensive documentation and examples
- Automated testing across integration points

**False Positives:**
- ML-based threshold adaptation
- Human-in-the-loop approval workflows
- Domain-specific policy templates

---

## 7. Implementation Roadmap

### Phase 1: Foundation (Q2 2026)
- [ ] Define unified policy schema
- [ ] Implement ClawMoat → Agent-OS data interchange
- [ ] Create LangChain reference integration
- [ ] Basic audit logging and alerting

### Phase 2: Framework Coverage (Q3 2026) 
- [ ] CrewAI middleware implementation
- [ ] OpenAI Agents SDK guardrails
- [ ] AutoGen conversation filtering
- [ ] Cross-platform policy validation

### Phase 3: Advanced Features (Q4 2026)
- [ ] Behavioral anomaly detection
- [ ] Automated threat intelligence sharing
- [ ] ML-driven policy optimization
- [ ] Enterprise compliance dashboards

### Phase 4: Ecosystem (Q1 2027)
- [ ] Google ADK integration
- [ ] PydanticAI type-safe policies
- [ ] Cloud-native deployment options
- [ ] Open source community governance

---

## 8. Conclusion

AI agents require **defense-in-depth security architecture** to operate safely in production environments. The combination of ClawMoat's reactive threat detection with Agent-OS's proactive governance provides comprehensive protection against the OWASP Agentic Top 10 while maintaining developer productivity.

This RFC proposes a practical, standards-based approach that:
- Works across agent frameworks
- Provides incremental adoption path
- Balances security with usability
- Scales to enterprise deployments

**Next Steps:**
1. Community review and feedback on this RFC
2. Proof-of-concept implementation with CrewAI
3. Policy schema standardization with industry stakeholders
4. Performance benchmarking and optimization

**Contributing:**
This RFC is open for community input. Please provide feedback on:
- Integration complexity and developer experience
- Policy schema completeness and flexibility
- Performance requirements and optimization strategies
- Additional framework support priorities

---

**References:**
- [OWASP Agentic Top 10](https://owasp.org/www-project-agentic-security/)
- [ClawMoat Documentation](https://github.com/darfaz/clawmoat)
- [Agent-OS Architecture](https://github.com/imran-siddique/agentmesh)
- [Oasis Security Research](https://www.oasis.security/blog/openclaw-vulnerability)

**Contact:**
- ClawMoat Team: [security@clawmoat.com]  
- Agent-OS Team: [governance@agent-os.dev]
- RFC Discussion: [GitHub Issues](https://github.com/darfaz/clawmoat/issues/20)