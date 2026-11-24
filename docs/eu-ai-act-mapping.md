# How the platform supports EU AI Act obligations

This is an engineering mapping, not legal advice and not a claim of compliance. The platform
produces controls and records that help a provider or deployer show what their AI agents did
and how humans oversaw them. Whether an obligation applies, and whether the evidence is
sufficient, depends on the system and should be confirmed with counsel. To classify a system
and list its obligations, see the author's open-source `eu-ai-act-compliance-kit`.

| Obligation (Regulation (EU) 2024/1689) | What the platform provides | What you still need |
|---|---|---|
| Art. 9 risk management | Per-action risk scoring with explained factors; policy rules per risk tier; `simulate` for testing changes | The risk management process and its documentation |
| Art. 12 record-keeping | Automatic, tamper-evident logging of every request, decision, approval and outcome with timestamps | Retention and export to your log archive |
| Art. 13 transparency to deployers | Decisions return reasons, matched rule and risk factors | Instructions for use of your own system |
| Art. 14 human oversight | Approval gates, four-eyes rules, ability to reject, and a kill switch that stops an agent immediately (Art. 14(4)(e)) | Trained, competent people assigned as reviewers |
| Art. 26(1)–(2) deployer use and oversight | Agents registered with an accountable owner, purpose and allow-list; reviewers assigned by policy | Organisational assignment and AI literacy (Art. 4) |
| Art. 26(5) monitoring | Metrics, decision history, suspension with reason | Incident reporting procedure |
| Art. 26(6) keep logs at least six months | Audit log in the database; verifiable chain | A retention policy and backups of at least six months |

For systems in Annex III (for example employment), the reference policy routes every write
or external action by an agent marked `eu_ai_act_risk = "high"` to a reviewer
(`human-oversight-for-high-risk-systems`). Application dates follow the Digital Omnibus
(Regulation (EU) 2026/1744): Annex III high-risk obligations apply from 2 December 2027.

## NIST AI RMF 1.0

| Function | Support |
|---|---|
| Govern | Accountable owner per agent, versioned policy with author, role-based access |
| Map | Agent purpose, autonomy level, data classification and risk class recorded at registration |
| Measure | Risk score per action, decision metrics, approval and denial rates |
| Manage | Approval gates, budgets, kill switch, audit verification |
