# Performance benchmark (scenario 1 scaled with benign records)

| Records | In scope | Kept as relevant | Load + scope (s) | Correlate + timeline + RCA (s) | Total (s) | Precision | Recall | RCA origin / entry IP |
|---|---|---|---|---|---|---|---|---|
| 500 | 484 | 49 | 0.007 | 0.001 | 0.008 | 0.429 | 1.0 | external / 203.0.113.55 |
| 5000 | 4984 | 20 | 0.06 | 0.007 | 0.066 | 1.0 | 0.952 | external / 203.0.113.55 |
| 50000 | 49984 | 20 | 0.788 | 0.091 | 0.873 | 1.0 | 0.952 | external / 203.0.113.55 |
