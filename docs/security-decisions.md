# Security Architecture Decision Records

## ADR-001: Use Mock Data Instead of Live Cloud Accounts

**Status:** Accepted
**Date:** 2024-01-15

### Context
The lab needs to demonstrate cloud security scanning capabilities without requiring actual AWS/Azure credentials or incurring cloud costs.

### Decision
All scanners and compliance checks operate against configuration dictionaries (mock data) rather than live cloud APIs. Live API integration can be added as an optional mode.

### Consequences
- ✅ No cloud credentials or costs needed to run, test, or demo
- ✅ Tests are deterministic and fast
- ✅ Safe for CI/CD pipelines
- ✅ Easy to create specific test scenarios
- ❌ Does not validate API response parsing
- ❌ Mock data may drift from real API shapes
- **Mitigation:** Maintain mock data schemas that mirror real API responses. Add optional `--live` mode later.

---

## ADR-002: Separate Scanners from Compliance Checks

**Status:** Accepted
**Date:** 2024-01-15

### Context
Security scanning (finding misconfigurations) and compliance assessment (checking against a framework) are related but distinct concerns.

### Decision
Implement separate modules:
- `security_scanner/` — Finds security issues, reports findings with severity
- `compliance/` — Evaluates configurations against specific framework controls (CIS, NIST), reports pass/fail with compliance scores

### Consequences
- ✅ Clear separation of concerns
- ✅ Scanners can run independently of compliance frameworks
- ✅ Compliance engine can reference scanner results or run its own checks
- ✅ Different output formats suit different audiences (security teams vs. auditors)
- ❌ Some check logic may be duplicated between modules
- **Mitigation:** Extract shared validation logic into utility functions.

---

## ADR-003: Detection Rules as Pure Functions

**Status:** Accepted
**Date:** 2024-01-15

### Context
Detection engineering rules need to be testable, composable, and easy to add.

### Decision
Each detection rule is a pure function with signature: `detect_X(event: dict) -> DetectionMatch | None`. Rules have no side effects and no shared state.

### Consequences
- ✅ Trivially testable — pass in event dict, check output
- ✅ Easy to add new rules — just write a function
- ✅ Rules are composable — engine iterates over registered rules
- ✅ Thread-safe by design
- ❌ Complex multi-event correlation is harder with stateless functions
- **Mitigation:** Add a `CorrelationEngine` class later for multi-event patterns.

---

## ADR-004: Conventional Commits for Automation

**Status:** Accepted
**Date:** 2024-01-15

### Context
The AI automation system generates commits. These need to look like real engineering commits and follow a parseable format.

### Decision
All commits (manual and automated) follow the [Conventional Commits](https://www.conventionalcommits.org/) specification: `<type>(<scope>): <description>`.

Types: `feat`, `fix`, `docs`, `chore`, `test`, `refactor`, `ci`, `research`

### Consequences
- ✅ Consistent, readable commit history
- ✅ Automated changelog generation possible
- ✅ Commits look professional and engineering-driven
- ✅ Easy to filter/search commit types
- ❌ Slightly more effort per commit message
- **Mitigation:** Git manager validates format before committing.

---

## ADR-005: OpenRouter as AI Provider

**Status:** Accepted
**Date:** 2024-01-15

### Context
The automation system needs an LLM API for task generation and code improvement. Budget is zero.

### Decision
Use OpenRouter API which provides:
- Free tier: 50 requests/day
- Access to multiple free models (Llama, Gemma, Qwen)
- OpenAI-compatible API format
- No credit card required

### Consequences
- ✅ Zero cost
- ✅ Model flexibility — can switch models without code changes
- ✅ Standard API format (OpenAI compatible)
- ❌ Free models may have lower quality output
- ❌ Rate limits require careful API call budgeting
- **Mitigation:** Built-in `TaskGenerator` as fallback when API is unavailable or rate-limited. Strategic use of 5 calls/day maximum.
