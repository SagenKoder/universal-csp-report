---
name: Bug report
about: Create a report to help us improve
title: '[BUG] '
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Configuration used (environment variables, etc.)
2. CSP report payload that caused the issue
3. Expected vs actual behavior

**Environment**
- Universal CSP Report version: [e.g., v1.0.0]
- Deployment method: [Docker, binary, docker-compose]
- Operating System: [e.g., Linux, macOS, Windows]
- Browser sending reports: [e.g., Chrome 120, Firefox 119]

**Logs**
If applicable, add relevant log output:
```
paste logs here
```

**CSP Report Payload**
If the issue is related to a specific CSP report format, please include the payload:
```json
{
  "csp-report": {
    // paste the CSP report here
  }
}
```

**Additional context**
Add any other context about the problem here.