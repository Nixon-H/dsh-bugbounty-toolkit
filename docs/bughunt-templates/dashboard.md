---
tags: [dashboard]
---

# 🎯 Bug Hunt Dashboard

## Active Campaigns
```dataview
TABLE target, status, started
FROM "bughunt/campaigns"
WHERE status = "ACTIVE"
SORT started DESC
```

## Recent Bugs
```dataview
TABLE target, class, severity, rhat_score, status
FROM "bughunt/bugs"
SORT file.ctime DESC
LIMIT 20
```

## Bugs by Status
```dataview
TABLE length(rows) as Count
FROM "bughunt/bugs"
GROUP BY status
```

## Bugs by Severity
```dataview
TABLE length(rows) as Count
FROM "bughunt/bugs"
WHERE rhat_score >= 2.0
GROUP BY class
SORT Count DESC
```

## Submitted Reports
```dataview
TABLE target, id, status
FROM "bughunt/reports"
SORT file.ctime DESC
```

## Quick Links
- [[bughunt/knowledge/grep-patterns|Grep Patterns Cheat Sheet]]
- [[bughunt/knowledge/cwe-top-25|CWE Top 25]]
- [[bughunt/knowledge/rhat-model|Rhat Scoring Reference]]
- [[bughunt/knowledge/variant-analysis|Variant Analysis Guide]]
