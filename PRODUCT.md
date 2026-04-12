**VEIL**

Product Document --- v2

*The agent firewall for developers.*

> **One security loop. Zero cloud. Complete agent security in under two minutes.**
>
> *Discover threats → Control credentials → Prove what happened → Feed back.*

getveil.dev

*April 2026 · Confidential*

## 1. One-Liner & Positioning

> ***.gitignore protected your secrets from git. We protect them from AI.***

Veil is an open-source CLI that creates a closed security loop around your AI coding agents. It **discovers** threats in the MCP servers your agents connect to, **controls** authentication so agents never see real credentials, and **proves** what every agent did with an immutable local audit trail. Each stage feeds the next: scan results sharpen proxy rules, proxy traffic populates the audit log, and audit anomalies improve future scans. The loop tightens every time you use it.

Every AI coding agent reads your project directory, including .env files and MCP configs with plaintext API keys, on every request. MCP servers are installed from unvetted registries with no supply chain checks. And no developer tool answers the question: what did my agent actually do with my credentials today?

The funded players in this space are building point solutions or enterprise platforms. Standalone scanners vet MCP servers but don't manage credentials. Secrets managers isolate keys but don't vet the endpoints those keys flow to. Enterprise gateways (Keycard $38M, Aembit $60M, Runlayer $11M) do both but require cloud infrastructure, sales conversations, and five-figure contracts. Nobody is shipping the complete **Discover → Control → Prove** cycle as a single local-first CLI that a developer installs in two minutes and never thinks about again.

Veil fills that gap. Open-source, MIT-licensed, local-first. One command---**veil init**---runs the full cycle: scans your MCP servers for supply chain threats, migrates every secret from .env files and MCP configs into your OS keychain behind format-aware placeholders, and activates audit logging for all future agent credential access. No accounts, no cloud, no config files. Under two minutes.

## 2. The Problem

> AI agents operate in a security vacuum. No vetting before connection. No credential isolation during use. No visibility after the fact. The five pains below are symptoms of the same systemic gap---and solving them separately creates seams between solutions that attackers walk through.

**The numbers:** 29 million secrets were leaked on public GitHub in 2025, a 34% increase year over year. AI-service credential leaks surged 81%. AI-assisted commits leak secrets at 2× the baseline rate. 24,000 secrets were found in public MCP configuration files. 30 CVEs were filed against MCP servers in January and February 2026 alone.

**Pain 1: AI agents read your .env file on every request**

Claude Code, Cursor, Copilot, and Windsurf index every file in your project directory. If your .env is there, your API keys enter the context window and are sent to the cloud. Agents have been documented hardcoding keys from environment files into generated source code. Credentials are exposed because nothing isolates them from the agent.

**Pain 2: MCP configs store credentials in plaintext JSON**

A typical MCP configuration file contains five or more plaintext tokens in a single JSON file. No encryption. Visible during screen shares. Synced by iCloud and OneDrive. Backed up by IDEs. 24,000+ secrets have been found in public GitHub MCP config files. The credential is sitting where the agent can see it.

**Pain 3: MCP servers are an unvetted supply chain**

MCP registries have no meaningful security vetting. A malicious *postmark-mcp* package built trust over 15 normal-looking versions before silently BCC'ing every outgoing email to an attacker. Compromised npm packages have deployed remote access trojans through MCP connectors. 502 MCP server configurations were found without version pinning across major registries. Nobody checks what agents connect to before they connect.

**Pain 4: No visibility into what agents do with credentials**

A developer using Claude Code, Cursor, and VS Code manages credentials across three separate systems. But no tool answers the basic question: what did my agent do with my GitHub token today? Which repos did it access? What PRs did it create? Enterprise observability tools exist for production AI systems, but nothing exists for a developer who wants local, queryable audit logs of agent actions tied back to specific credentials. Without this visibility, there is no feedback signal to improve the other protections.

**Pain 5: OAuth tokens don't persist between sessions**

Every time a developer restarts Claude Code, SSE-type MCP servers require manual re-authentication. Refresh tokens are stored but not used. Multiple open GitHub issues document developers re-authenticating several times per day. This is a friction problem that erodes adoption of any security tool that adds steps to the workflow.

*These five problems are connected. Veil solves them as one integrated system.*

## 3. The Product

> **Core Principle**
>
> Your AI agent can use your credentials without ever seeing them, connect to MCP servers that have been vetted for threats, and every action is logged locally for your review---with each stage making the others smarter.

### How It Works

Before the technical detail, here is what the loop looks like for a real developer:

> **The Loop in Action**
>
> A developer runs **veil init** in their project directory.
>
> **Discover:** Veil scans three connected MCP servers and flags one with a known exfiltration pattern. Credential access for that server is blocked automatically.
>
> **Control:** For the two clean servers, eight secrets are migrated from .env files and MCP configs into the OS keychain and replaced with format-aware placeholders. The agent will find what looks like real credentials; the proxy will swap in the real ones at the network layer.
>
> **Prove:** The next day, the developer runs **veil run claude**. Every credential injection, API call, file write, and command execution is logged. A week later, **veil log** reveals one server making requests to an unfamiliar endpoint.
>
> **Feed Back:** That anomaly is reported to the community threat database. The next developer who scans that server gets a warning before connecting. The loop tightened itself.

### How It Works: Defense in Depth

Most approaches to agent credential security rely on agents voluntarily using a special tool or API to access secrets. That doesn't work. You cannot control agent behavior. An agent that sees a .env file will read it. An agent trained on millions of code samples will default to reading environment variables, not calling a proxy tool.

Veil takes a different approach: a defense-in-depth architecture that operates at the network and filesystem layers, *below the agent*. The agent does not need to know Veil exists. In fact, Veil works best when the agent thinks everything is normal---it finds credentials in .env files, uses them to make API calls, and gets successful responses. What the agent doesn't know is that every credential it found is a format-aware placeholder, and the real secret was injected at the network layer by Veil's proxy.

### Discover: MCP Supply Chain Scanner

> Before you install an MCP server, Veil scans it. The CLI checks the package against a community threat database for known tool poisoning, credential harvesting, prompt injection patterns, and exfiltration behaviors. It verifies version pinning, checks package age and maintainer reputation, and scans tool descriptions for hidden instructions that could manipulate agent behavior. Scan results feed directly into the proxy's credential scoping: if a server is flagged, its destination hosts are blocked from credential injection automatically.

### Control: Network Proxy + Placeholder .env

> **veil run \<agent-command\>** starts a local HTTPS proxy daemon and spawns the agent process with HTTP\_PROXY / HTTPS\_PROXY pointed at it. The proxy inspects outbound requests by destination hostname and injects the correct credential from the OS keychain. The agent makes normal HTTP calls---it doesn't need to use any special tool or API.
>
> **veil init** moves real secrets from .env files and MCP configs into the OS keychain, then replaces them with format-aware placeholders that look identical to real credentials. A GitHub PAT placeholder starts with **ghp\_** and is the correct length. A Slack token starts with **xoxb-**. The proxy recognizes Veil-generated placeholders on outbound requests and swaps them for real credentials from the keychain.

### Prove: Runtime Audit Log

> The network proxy is the single chokepoint for all agent network traffic, which makes auditing comprehensive. Every credential injection is logged: timestamp, destination hostname, credential used, agent PID. But Veil's audit goes beyond credentials---it also records runtime agent actions: file writes, command executions, API call payloads, and MCP tool invocations. Queryable via CLI: **veil log --today**. Logs stay on your machine in local SQLite.
>
> The Prove stage is what closes the loop. Audit data reveals which MCP servers make unexpected calls (feeding back into the scanner's threat intelligence) and which credentials are over-scoped (feeding back into the proxy's policy engine).

### The Tightening Mechanism: Policy Engine

The policy engine is how the loop compounds automatically. It sits at the proxy layer and enforces YAML-based rules: which agent can access which service with which operations. But its real power is that it learns from the audit log. If audit data shows a credential is only ever used for *pulls.list* on *api.github.com*, the policy engine suggests scoping it down. The developer approves the tighter policy, the proxy enforces it, and the next audit cycle confirms the constraint holds. Each rotation of the cycle produces a tighter security posture without manual configuration.

### Supporting Capabilities

*These features support the core loop without being loop stages themselves:*

- **OAuth Token Persistence:** Stores and auto-refreshes OAuth tokens across IDE sessions. No more re-authenticating MCP servers on every restart. Eliminates the friction that erodes adoption of any security workflow.

- **Secret Scanning:** Watches for accidental credential exposure in agent-generated code and alerts before commit. A defense-in-depth safety net within the Control stage---if a placeholder somehow gets hardcoded, this catches it.

- **Cross-IDE Consistency:** One credential store works across Claude Code, Cursor, VS Code, and any MCP client. The loop runs the same regardless of which agent you use.

### Setup: Under 2 Minutes

```
$ brew install veil

$ veil init

Scanning project...

Found 8 secrets across 2 .env files and 1 MCP config

Scanned 3 MCP servers: 3 clean, 0 threats

✓ 8 secrets stored in macOS Keychain
✓ .env values replaced with format-aware placeholders
✓ MCP servers vetted and config updated
✓ IDE hooks installed (Claude Code PreToolUse)
✓ Audit logging active

$ veil run claude  # launches agent with proxy + audit active
```

## 4. Architecture

Veil runs entirely on the developer's machine. The core component is a local HTTPS proxy daemon that intercepts agent network traffic and injects credentials transparently. No agent cooperation required.

| Loop Stage / Layer | Description |
|---|---|
| Discover: Scanner Engine | Checks MCP servers against a threat database before connection. Scans for tool poisoning, prompt injection in tool descriptions, credential harvesting patterns, package reputation, and version pinning. Community-contributed threat signatures. Feeds results into proxy credential scoping. |
| Control: HTTPS Proxy | Local proxy daemon started via veil run. Agent process spawned with HTTP\_PROXY / HTTPS\_PROXY env vars. Inspects outbound requests by destination hostname and injects the matching credential from the OS keychain. TLS terminated and re-established locally with a Veil-generated CA certificate. |
| Control: Placeholder .env | veil init migrates secrets to keychain and replaces each value with a format-aware placeholder (correct prefix, length, character set). Agents find realistic-looking tokens and proceed normally. Proxy recognizes placeholders on outbound requests and swaps them for real credentials. |
| Control: OS Keychain | Secrets stored in macOS Keychain, Windows Credential Manager, or Linux Secret Service. Encrypted at rest by the OS. Veil reads credentials at proxy time; they are never written to files or environment variables visible to the agent. |
| Prove: Audit Engine | The proxy is the single chokepoint for all agent traffic. Logs credential injections, runtime agent actions (file writes, command executions, API payloads, MCP tool invocations) to local SQLite. Feeds anomalies back into scanner threat intelligence and policy engine recommendations. |
| Tighten: Policy Engine | YAML-based rules defining what each agent can access. Per-agent, per-service, per-operation control. Enforced at the proxy layer. Learns from audit data to suggest tighter scoping automatically. |

### Data Flow

Developer runs **veil run claude** → Veil starts local HTTPS proxy and spawns Claude Code with proxy env vars → Agent reads .env, finds *ghp\_veil\_a8f3c2e9...* (a format-aware placeholder) → Agent constructs Authorization header and makes request to api.github.com → Proxy intercepts, recognizes placeholder, resolves real GitHub token from OS keychain → Forwards request to GitHub → GitHub returns 200 → Agent gets successful response → Audit engine logs: timestamp, github.com, pulls.create, claude-code PID. The real token never enters the agent's context window or any file on disk.

### The Feedback Loop

Each stage of the cycle produces signal that strengthens the others:

| Path | What Happens |
|---|---|
| Scanner → Proxy | Scanner flags an MCP server with a known exfiltration CVE. Proxy automatically blocks credential injection for that server's destination hosts. No manual config. |
| Proxy → Audit | Every credential injection is logged with destination, credential identity, and agent PID. The audit log inherits the proxy's context about which credentials were used and why. |
| Audit → Scanner | Audit data reveals an MCP server making requests to an unexpected domain. This behavioral signal feeds back into the threat database, improving future scans for all users. |
| Audit → Policy | Access pattern analysis reveals a credential is only used by one server for one operation. The policy engine suggests tightening the scope automatically. |
| Policy → Proxy | Tighter policies constrain the proxy's credential injection rules. The next audit cycle confirms the constraint holds. The loop has tightened. |

## 5. Competitive Landscape

| Product | Discover | Control | Prove | Closed Loop | Built For |
|---|---|---|---|---|---|
| Veil | Scanner (core) | Network proxy (core) | Runtime audit (core) | ✓ Full cycle | Solo devs, small teams |
| Keycard | No | Ephemeral tokens | Yes | ✗ No discovery | Enterprise |
| Runlayer | Threat detection | Gateway | Yes | ✗ Cloud-only | Enterprise |
| 1Password | No | Runtime inject | No | ✗ No audit | Organizations |
| Infisical | No | Secrets mgmt | MCP governance | ✗ No discovery | DevOps teams |
| Sage | URL/pkg checks | No | No | ✗ No control | Developers |
| Aembit | No | NHI / IAM | Yes | ✗ No discovery | Enterprise |
| MS Gov TK | No | Policy middleware | Runtime monitoring | ✗ No discovery | Enterprise frameworks |
| Snyk Evo | AI-SPM scanning | Policy enforcement | Real-time visibility | ✗ Cloud-only | Enterprise |

**The key insight:** every competitor is either a point solution that covers one or two stages, or an enterprise platform that requires cloud infrastructure. Standalone scanners discover but don't control or prove. Secrets managers control but don't discover or prove. Enterprise gateways may cover all three stages but require organizational accounts, sales conversations, and cloud dependencies. No tool delivers the complete **Discover → Control → Prove** cycle in a single local-first, zero-infrastructure package. Veil's moat is the closed loop, not any single feature.

## 6. Differentiation

### The Closed Loop as Structural Advantage

The differentiation is not that Veil covers three capabilities. It's that the three stages create a feedback loop that is qualitatively better than running them separately---and that no point solution or glued-together stack can replicate.

> **One command. The full cycle.**
>
> A developer runs **veil init** in their project directory. In one pass, Veil discovers threats in every connected MCP server, controls credentials by migrating them to the OS keychain behind format-aware placeholders, and activates audit logging to prove what every future agent action does. Without Veil, achieving the same coverage requires installing and configuring a scanner, a secrets manager, a runtime proxy, and an observability tool---four tools, four configs, four maintenance burdens, and zero shared context between them.

Each stage reinforces the others. Discovery feeds the proxy, audit logs strengthen threat intelligence, and the policy engine tightens automatically based on patterns. This feedback loop is only possible because all stages share a single daemon, data model, and configuration.

### Why Point Solutions Leave Gaps

**No discovery: Keycard, Aembit, 1Password**

All three manage credentials but none vet the endpoints those credentials flow to. Without endpoint discovery and runtime audit logging, they cannot detect server compromise or validate behavior.

**No control: Sage**

Sage intercepts dangerous commands but does not isolate credentials from agent access. An agent using Sage still reads .env files directly.

**One-shot discovery: standalone scanners**

Most standalone scanners vet servers before connection but lack credential isolation and runtime audit trails. They cannot detect deferred attacks or behavioral anomalies.

**Cloud-only loops: Runlayer, Snyk Evo, Microsoft Agent Governance Toolkit**

These platforms offer cloud-based governance but require enterprise setup, SSO integration, or framework-level development integration. Not designed as local-first CLI tools for solo developers.

**No feedback: Infisical Agent Sentinel**

Infisical Sentinel scopes credentials per server but delivers secrets to processes and requires a cloud server. It cannot detect runtime exfiltration. Veil never exposes secrets to agents or servers---credentials stay in the proxy layer.

## 7. Feature Set

### Open Source (MIT) --- Free Forever

**Discover Stage**

- **MCP Supply Chain Scanner:** Scan any MCP server before connecting. Checks threat database for tool poisoning, prompt injection, credential harvesting, exfiltration patterns. Version pinning verification. Package reputation checks. Community-contributed threat signatures.

**Control Stage**

- **Network Proxy:** Local HTTPS proxy started via veil run. Intercepts outbound requests by destination hostname and injects credentials from OS keychain. Agent makes normal HTTP calls; Veil handles auth transparently. No agent cooperation required.

- **Placeholder .env + MCP Config Migration:** One command imports secrets from .env files and MCP configs into the OS keychain, replaces each value with a format-aware placeholder (correct prefix, length, character set per service). Proxy swaps placeholders for real credentials on outbound requests.

- **OS Keychain Storage:** Secrets stored in macOS Keychain, Windows Credential Manager, or Linux Secret Service. Encrypted at rest by the OS.

**Prove Stage**

- **Runtime Audit Log:** Every credential injection, file write, command execution, API call, and MCP tool invocation logged to local SQLite. Queryable via CLI with filters for agent, service, operation, time, session.

**Feedback Mechanism**

- **Policy Engine:** YAML-based rules: which agent can access which service with which operations. Learns from audit data to suggest tighter scoping. Enforced at the proxy layer.

**Supporting Capabilities**

- **OAuth Token Persistence:** Stores and auto-refreshes OAuth tokens across IDE sessions. No more re-authenticating on every restart.

- **Cross-IDE Consistency:** One credential store works across Claude Code, Cursor, VS Code, and any MCP client.

- **Secret Scanning:** Watches for accidental credential exposure in agent-generated code. Alerts before commit.

### Team Tier --- $12/dev/month

- **Shared Credential Store:** Team-wide secrets synced with end-to-end encryption. New team member runs veil join and gets every credential scoped to their role.

- **Per-Agent Policies:** Per-agent policies enforced across the team. Same YAML format, centrally managed.

- **Cloud Audit Dashboard:** Centralized view of all credential access, runtime actions, and MCP usage across the team. Exportable for compliance.

- **Credential Rotation:** Automated rotation with configurable TTLs. Veil rotates expiring keys and updates every reference.

- **Shared Threat Feed:** When one member flags an MCP server, the whole team is protected.

- **OpenTelemetry Export:** Export audit data to standard SIEM tools via OpenTelemetry. Makes the Prove stage composable with existing enterprise observability stacks.

### Enterprise --- $35/dev/month + platform fee

- **SSO / SCIM:** Okta, Entra, Google Workspace. Automatic provisioning and deprovisioning.

- **MCP Supply Chain Intelligence:** Curated threat database with priority updates. Advanced scanning heuristics. Custom rules for organizational MCP policies.

- **Compliance Reports:** SOC 2, ISO 27001 evidence generation. Automated reports showing credential inventory, access logs, rotation compliance, and policy enforcement.

- **Vault Integration:** Pull secrets from HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault. Veil becomes the agent-facing interface to existing infrastructure.

- **Advanced OTel + Alerting:** Full audit trail export with OpenTelemetry integration, customizable retention policies, and real-time alerting on anomalous agent behavior.

## 8. Open-Source Strategy

> **License: MIT**
>
> No BSL. No AGPL. No license switch. Ever. The core product is free, self-hostable, and forkable forever. Monetization comes from managed services and team features, not license restrictions.

**Why MIT beats BSL:** After HashiCorp switched to BSL and the community forked to OpenTofu, developer sentiment against source-available licenses is at an all-time low. MIT signals trust. Trust is everything for a security tool. Infisical proved the model: MIT core, $16M in funding, 100K developers, 20× revenue growth.

**What's MIT (free forever):** CLI, daemon, MCP server, OS keychain integration, supply chain scanner, .env migration, secret scanning, policy engine, runtime audit log, cross-IDE support.

**What's paid:** Shared credential store, cloud audit dashboard, OpenTelemetry export, automated rotation, SSO/SCIM, curated supply chain intelligence, compliance reports, vault integrations. Features that require infrastructure or that enterprises need for governance.

**The threat database is the moat.** Every MCP server scanned, every attack pattern detected, every community-contributed threat signature feeds a dataset that compounds over time. This is the same dynamic that made Snyk's vulnerability database defensible. A fork gets the code but not the data---and critically, not the feedback loop between scanner, proxy, and audit engine that generates the data.

## 9. Go-to-Market

**Month 0: Pre-launch --- Build in Public, Lead with the Loop**

Ship the CLI with the full **Discover → Control → Prove** cycle as the headline. Record a 90-second demo showing a developer go from exposed .env files to a fully closed security loop in under two minutes. Post progress on X. Write a blog post showing the four-tool stack Veil replaces---and why gluing tools together loses the feedback signal. Target: 50 beta users from developer security communities.

**Month 1: Launch --- Hacker News + GitHub**

Post on HN linking to the GitHub repo. Title: *"Show HN: Veil --- a closed security loop for AI agents. Discovers threats, controls credentials, proves what happened. Zero cloud."* Lead with the architecture insight, not the feature count. The HN audience will dig into features on their own; the hook should be the loop. Target: front page, 500+ stars in first week, 1,500 installs.

**Months 2--4: Community --- Ecosystem Integration**

Write integration guides for Claude Code, Cursor, VS Code. Publish to awesome-mcp lists. Contribute Homebrew formula. Write content showing the feedback loop in action: "How Veil's audit log caught a compromised MCP server that passed the initial scan." Build the community threat signature repository. Target: 5,000 installs, 2,000 weekly active users.

**Months 4--6: Teams --- Launch Paid Tier**

Ship shared credential store, cloud audit dashboard, OpenTelemetry export, team policies. Target small teams (5--15 devs) who adopted the free tier and need shared credential management and centralized audit. Pricing: $12/dev/month. Target: 100 paying teams, $15K MRR.

**Months 6--12: Enterprise --- Compliance + SSO**

Ship SSO, compliance reports, vault integrations, curated supply chain intelligence, advanced OTel alerting. Target companies with 50+ developers where the CISO is asking about AI agent security. Pricing: $35/dev/month + platform fee. Target: 10 enterprise customers, $50K MRR.

## 10. Success Metrics

GitHub stars are vanity. These are the metrics that matter.

| Metric | Month 1 | Month 3 | Month 6 | Month 12 | Loop Stage |
|---|---|---|---|---|---|
| Weekly installs | 1,500 | 4,000 | 10,000 | 25,000 | --- |
| Weekly active users | 300 | 2,000 | 6,000 | 18,000 | --- |
| MCP servers scanned | 500 | 5,000 | 25,000 | 100,000 | Discover |
| Threat sigs (community) | 50 | 200 | 500 | 1,500 | Discover |
| Secrets managed | 3,000 | 25,000 | 120,000 | 600,000 | Control |
| Audit events logged | --- | 50,000 | 500,000 | 5,000,000 | Prove |
| Policy auto-suggestions | --- | --- | 1,000 | 10,000 | Feedback |
| Paying teams | --- | --- | 100 | 500 | --- |
| MRR | $0 | $0 | $15K | $75K | --- |

## 11. Risks & Honest Answers

**"Anthropic, Cursor, or GitHub will just build this."**

Each vendor will build for their own tool. Anthropic will solve it for Claude Code. Cursor will solve it for Cursor. Nobody will build the cross-IDE solution because no single vendor is incentivized to. 1Password is the exception, but they require a paid account and their Unified Access platform is oriented toward organizational deployment, not solo developers. Also, no platform vendor is incentivized to build MCP supply chain scanning that flags third-party servers as dangerous---that's inherently adversarial to their ecosystem growth.

**"The MCP spec will fix auth natively."**

The MCP spec is adding OAuth 2.1, which helps with new MCP servers built to spec. It does not fix existing .env file exposure, existing plaintext MCP configs, or the supply chain problem. It also does not provide audit logging, runtime action monitoring, or cross-IDE credential management. Veil addresses problems the spec cannot.

**"Keycard or 1Password will add a developer tier."**

Enterprise companies are historically poor at building for individuals. 1Password launched Unified Access in March 2026 with Anthropic, Cursor, and GitHub partnerships---but it's an organizational platform, not a solo-developer CLI. Their incentives, pricing, and UX are oriented toward organizations. The threat database and community threat signatures create switching costs that are hard to replicate with a bolt-on free tier.

**"Microsoft's Agent Governance Toolkit is open-source and free."**

Microsoft's AGT (launched April 2, 2026) is a strong runtime governance framework---but it's designed for framework-level integration (LangChain, CrewAI, Google ADK, Microsoft Agent Framework). It requires instrumenting your agent code with callback handlers and middleware. Veil operates below the agent at the network layer and requires zero agent cooperation. AGT also has no supply chain scanning, no credential isolation, and no feedback loop between stages. It's a Prove-stage tool without Discover or Control.

**"Snyk Evo AI-SPM will dominate this space."**

Snyk Evo (launched March 2026) brings real-time visibility and policy enforcement for autonomous coding agents across the development lifecycle. It's a serious product. But it's a cloud platform feature---part of Snyk's enterprise offering, requiring organizational onboarding. It does not manage credentials locally or provide the Discover → Control → Prove cycle as a self-contained CLI. Veil and Snyk Evo serve different segments: Snyk Evo for enterprises with existing Snyk contracts, Veil for the 10 million developers who need this today and won't go through enterprise procurement.

**"Open source means no moat."**

The moat is not the license or any single feature. It's the closed feedback loop that no point solution can replicate, the threat database that compounds with every scan, and the trust built by being MIT from day one. A fork gets the code but not the data, the community threat signatures, or the feedback loop between scanner, proxy, and audit engine that generates the data. Infisical is MIT-licensed and raised $16M on the same model.

**"Developers won't pay for security tools."**

Developers will not pay. Their employers will. The free tier builds adoption. The team tier solves credential sharing pain. The enterprise tier solves compliance. This is the Snyk playbook: developers love the CLI, buyers pay for the platform.

**"Sage already does agent interception for free."**

Sage and Veil are complementary. Sage intercepts dangerous runtime commands; Veil secures credentials and vets MCP servers. A developer running both has better coverage than either alone. The right move is to build a Sage integration, not compete with it.

**"The MCP scanning space is already crowded."**

It is. Snyk's agent-scan, Invariant Labs' mcp-scan, Cisco's scanner, MCPScan.ai, MCPTox, MindGuard, and Sigil all scan MCP servers. This is why Veil does not position the scanner as its primary differentiator. The scanner is the Discover stage of a closed loop---not a standalone product. The value is that discovery, credential isolation, and audit logging share a single daemon and data model. No standalone scanner provides that closed loop.

## 12. MVP Scope

The loop stages ship sequentially, not simultaneously. Each phase opens one more stage of the **Discover → Control → Prove** cycle. Each has a specific validation milestone that gates the next. This reduces execution risk and lets the team learn from real usage before investing in the next stage.

> **Phase 1: Control (Months 0--2)**
>
> *Open the loop. Ship the hardest technical risk first.*
>
> **veil run \<agent\>** --- local HTTPS proxy daemon that spawns the agent with HTTP\_PROXY / HTTPS\_PROXY env vars. Intercepts outbound requests by destination hostname and injects credentials from the OS keychain.
>
> **veil init** --- auto-detects .env files and MCP configs, imports real secrets to OS keychain, replaces each value with a format-aware placeholder.
>
> **IDE hooks** --- Claude Code PreToolUse hooks to block reads of credential files. Defense-in-depth behind the proxy.
>
> **OAuth token persistence** that survives IDE restarts. Proxy handles auto-refresh transparently.
>
> **Validation gate:** 100 developers using veil run daily. Zero real credential leaks into agent context windows. Proxy transparent to agents---no IDE breakage. Format-aware placeholders pass client-side validation for top 20 services.

> **Phase 2: Discover (Months 3--4)**
>
> *Complete the front of the loop. Connect discovery to control.*
>
> **veil scan** --- checks any MCP server against a threat database before you connect. Scans for tool poisoning, prompt injection in tool descriptions, credential harvesting patterns, and exfiltration behaviors.
>
> **Seed database** with the 30+ CVEs from Jan--Feb 2026, the documented postmark-mcp attack, the Snyk ToxicSkills campaign, and public npm advisory feeds.
>
> **Integrated into veil init** --- when importing MCP configs, every connected server is scanned automatically. Scan results feed directly into the proxy's credential scoping rules.
>
> **Validation gate:** 1,000 MCP servers scanned. At least one real threat caught in the wild. Scanner results demonstrably tightening proxy rules. Community contributors submitting threat signatures.

> **Phase 3: Prove & Feed Back (Months 5--6)**
>
> *Close the loop. Enable the feedback mechanism and the team upsell.*
>
> **veil log** --- every credential injection, file write, command execution, API call, and MCP tool invocation logged to local SQLite. Queryable via CLI: veil log --today, veil log --service github --last 7d, veil log --agent claude-code.
>
> **Feedback loop activated:** audit data reveals which MCP servers make unexpected calls, feeding back into the scanner's threat intelligence. Policy engine analyzes access patterns and suggests tighter credential scoping. The cycle is now closed.
>
> **Validation gate:** Developers actively querying logs. Audit data driving at least one scan improvement and one policy tightening. Ready to build cloud audit dashboard and OTel export for team tier (month 6 paid launch).

### Why This Sequence

**Control ships first** because it solves the most immediate pain and is the hardest technical work to validate.

**Discover ships second** to connect threat intelligence to credential scoping once the proxy is stable.

**Prove & Feed Back ships third** because the proxy is already the logging chokepoint for all traffic.

*End of document.*
