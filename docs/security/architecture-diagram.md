# DevSecOps Security Architecture Diagram

Developer Push
↓
GitHub Actions
│
├── Semgrep (SAST)
│
├── Trivy (SCA / Container)
│
├── ZAP (DAST)
│
↓
Integrated Summary Generator
↓
Centralized Security Gate
↓
Pass / Fail Decision