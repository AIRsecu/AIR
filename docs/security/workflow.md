# GitHub Actions Workflow

## Workflow Jobs

### semgrep
Static source code analysis

### trivy
Container vulnerability analysis

### zap
Dynamic application security testing

### summary
Integrated security summary generation

### security gate
Centralized policy evaluation

---

## Workflow Order

semgrep
↓
trivy
↓
zap
↓
summary
↓
security gate