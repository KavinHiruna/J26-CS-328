# Ablation (4 fixed scenarios and 100 held-out scenarios, seed 2027)

Each row switches off one rule. Values are macro averages; RCA columns are the share of scenarios correct.

## 4 fixed scenarios

| Configuration | Precision | Recall | F1 | Stage acc | Asset F1 | Vector | Entry IP | Origin |
|---|---|---|---|---|---|---|---|---|
| Full method (all rules on) | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| No reverse-seed rule (C2 address as destination) | 1.00 | 0.90 | 0.94 | 1.00 | 1.00 | 0.75 | 1.00 | 1.00 |
| No flow-history rule (routine flows of pivoted hosts) | 0.98 | 1.00 | 0.99 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| No policy-alert filter | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| Single failed login counted as evidence | 0.96 | 1.00 | 0.98 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| Login counted without actor link | 0.96 | 1.00 | 0.98 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| Routine device events counted | 0.91 | 1.00 | 0.95 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| Chain split by pauses (old group rule) | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| No IT-OT corroboration requirement | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| Keyword stage classifier (old) | 1.00 | 1.00 | 1.00 | 0.64 | 0.88 | 0.25 | 1.00 | 1.00 |
| First-event root cause (old) | 1.00 | 1.00 | 1.00 | 1.00 | 0.87 | 0.00 | 0.50 | 0.00 |

## Held-out scenarios

| Configuration | Precision | Recall | F1 | Stage acc | Asset F1 | Vector | Entry IP | Origin |
|---|---|---|---|---|---|---|---|---|
| Full method (all rules on) | 0.82 | 1.00 | 0.89 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| No reverse-seed rule (C2 address as destination) | 0.80 | 0.91 | 0.84 | 1.00 | 1.00 | 0.75 | 1.00 | 1.00 |
| No flow-history rule (routine flows of pivoted hosts) | 0.66 | 1.00 | 0.77 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| No policy-alert filter | 0.82 | 1.00 | 0.89 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| Single failed login counted as evidence | 0.79 | 1.00 | 0.87 | 1.00 | 1.00 | 0.99 | 1.00 | 1.00 |
| Login counted without actor link | 0.78 | 1.00 | 0.86 | 1.00 | 1.00 | 0.97 | 1.00 | 1.00 |
| Routine device events counted | 0.75 | 1.00 | 0.85 | 1.00 | 1.00 | 0.97 | 1.00 | 1.00 |
| Chain split by pauses (old group rule) | 0.82 | 0.99 | 0.88 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| No IT-OT corroboration requirement | 0.82 | 1.00 | 0.89 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| Keyword stage classifier (old) | 0.82 | 1.00 | 0.89 | 0.63 | 0.93 | 0.33 | 1.00 | 1.00 |
| First-event root cause (old) | 0.82 | 1.00 | 0.89 | 1.00 | 0.80 | 0.00 | 0.50 | 0.00 |

