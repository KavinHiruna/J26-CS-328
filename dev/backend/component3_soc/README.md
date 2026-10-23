# Component 3: Automated SOC Alert Prioritisation

Owner: Hiruna B.H.K (IT23204270) · Supervisor: Kanishka Yapa

Takes the alerts Component 1 produces and ranks them, so the SOC analyst knows which to handle first.
Every alert gets a **risk score from 0 to 100** and a level (Critical, High, Medium, Low) with suggested steps.
The steps are advice only: a human analyst decides and approves any action.

## The idea in one formula

```
risk = 100 x ( 0.3154 x Severity + 0.1718 x Confidence + 0.4158 x Asset + 0.0970 x Frequency )
```
Severity, Asset and Frequency run from 1 to 5 and are rescaled to 0..1 with (x - 1) / 4. Confidence is already 0..1.

## Where every value comes from (the project's evidence rule)

| Value | Method | Source | Status |
|---|---|---|---|
| Severity (1-5) | MITRE CAPEC "Typical Severity" (Very Low..Very High -> 1..5); SQL injection, Backdoor, Ransomware from the survey-2 median | CAPEC; survey 2, n = 10 (mostly junior practitioners and students) | Sourced |
| Confidence (0-1) | Component 1's probability, calibrated per class (isotonic, 5-fold) | Niculescu-Mizil and Caruana 2005; ECE 0.0939 -> 0.0018 | Verified |
| Asset (1-5) | Role of the target IP from the Edge-IIoTset paper (Table VI: 192.168.0.128 edge server, .101 sensor node; Table V: .170 attacker), cross-checked on the traffic (Modbus port 502 only reaches .128); rating = survey-2 median (5, 4, 4) | Ferrag et al. 2022 (TechRxiv doi 10.36227/techrxiv.18857336.v1); survey 2; CVSS v3.1 environmental requirements idea | Survey-backed |
| Frequency (1-5) | Alerts of the same attack on the same target in the previous 60 s, log scale, cap 500 | The data: 97.4% of gaps are <= 60 s; 99th percentile about 467 | Data-derived |
| Weights | AHP pairwise comparisons, geometric-mean group matrix, principal eigenvector | Saaty 1980; survey 1, n = 15, consistency ratio 0.031 | Survey-backed |
| Scaling (x-1)/4 | Min-max normalisation | Mokotoff et al. 2010 | Convention |
| Levels | FIRST CVSS v3.1 bands on score / 10: 90 / 70 / 40 | FIRST specification section 5 | Borrowed scale |

All numbers are written in `config.py`, each with a comment naming its source. The scoring code reads ONLY `config.py`.
The evidence (CAPEC table, survey medians, paper tables, traffic counts) is in `data/evidence/`;
`analysis/evidence_check.py` and the tests fail if a number in `config.py` differs from its evidence file.

## Honest limits (say them before the examiner does)
- Survey respondents were mostly interns and people with 1 to 2 years' experience, not senior analysts.
- The experts rated every device as important (5, 4, 4), so the asset factor separates little in this dataset.
- The asset table has 3 IPs. Their roles come from the Edge-IIoTset paper (Tables V and VI); the dataset has no real plant inventory.
  The paper also lists 192.168.0.101 beside the man-in-the-middle attacks without explaining why.
  19.3% of alerts go to a destination not in the registry and use a flagged fallback.
- CVSS bands were designed for vulnerabilities; Red Hat and Microsoft do not use them. 74% of alerts land in Critical or High,
  so the **ranked queue**, not the label, is what guides the analyst.
- Frequency has no published standard behind it; it is a design choice with the lowest weight.
- DDoS_UDP and MITM flows have no timestamp: they use a capture-wide count, flagged in the output (12% of alerts).
- The calibrator is fitted on test-split labels (the only place C1's predictions exist). Ask Component 1 for
  validation-set predictions to calibrate on.
- Validation so far: two human raters (3 years academic; 1.5 years as a network engineer) who agree with each other only
  weakly (Spearman 0.41). The score agrees with their average at 0.70, equal weights at 0.68, severity alone at 0.28:
  better than severity alone, not clearly better than equal weights. Weights matter most for the very top of the queue.
- Not built: notifications to an analyst (email, chat). The result is shown in the dashboard and the service only.

## Inputs
`data/c1_alerts_test20.csv`: one row per network flow, in the format of `docs/interfaces.md`:
`flow_id, src_ip, dst_ip, predicted_type, confidence_raw, event_time` (+ `true_type` only to measure accuracy and calibrate).
`event_time` is seconds and is empty when the flow has no timestamp.
All Component 3 paths are inside `backend/component3_soc/` (see `config.py`). The only file read from outside is the
shared raw capture `dev/data/raw/EdgeIIoT_train_80_with_incident_id.csv` (optional, read-only, for the traffic
cross-check in `analysis/evidence_check.py`; skipped if missing).

## Outputs
- `outputs/scored_alerts.csv`: the ranked queue (alert_id, scores, level, advice, flags).
- `docs/results/calibration_report.txt` (committed) and `outputs/live_scored.jsonl` (generated; not committed).
- Live service: `POST http://127.0.0.1:8765/alert` (see `docs/interfaces.md`).
- `outputs/incidents/<incident_id>.json`: incident files for Component 4 (see below; generated, not committed).

## Incidents for Component 4
Component 4 (forensics) reads one `incident.json` per **incident**: a group of related alerts, not one flow.

**Grouping rule** (`incidents.py`; our design choice, not a published standard):
- same `src_ip`, `dst_ip` and `predicted_type`, and each alert at most `WINDOW_SECONDS` (60 s, `config.py`) after the
  previous alert of that group; a larger gap starts a new incident;
- alerts without `event_time` (DDoS_UDP, MITM) cannot be ordered in time: one capture-wide group per src/dst/type,
  marked `"time_basis": "no timestamp (capture-wide group)"` with `"time_window": null`;
- the incident's `risk_score`, `priority`, `reason` and `recommendations` are those of its **highest-scoring alert**;
- IDs `INC-000001...` follow a fixed order (first event_time, then src_ip, dst_ip, type; untimed groups last),
  so the same data always gives the same IDs. `event_time` is joined from Component 1's file by flow_id.

Current data: **5,641 incidents** (5,331 timed + 310 untimed) from 26,699 alerts; 11 Critical, 3,820 High, 1,810 Medium.
The 3,642 Critical alerts fall into only 11 incidents: they come in large bursts against the control endpoint.
```
python -m backend.component3_soc.export_incident --summary                          # counts per priority
python -m backend.component3_soc.export_incident --incident INC-000123 [--out folder]
python -m backend.component3_soc.export_incident --top 20 [--priority Critical] [--out folder]
```
Files go to `outputs/incidents/<incident_id>.json` (generated, not committed). Run the pipeline first.

Honest limits:
- The grouping rule is our design choice. The 60 s window comes from the data (97.4% of gaps between such alerts are
  <= 60 s, `analysis/window_evidence.py`), not from a standard.
- Untimed attacks are grouped over the whole capture, so one such "incident" may really be several separate episodes.
- An attacker who changes source IP, target or attack type starts a new incident; related incidents are not linked.

## How to run (Windows PowerShell or any terminal; run from the `dev` folder, the one that contains `backend/`)
```
python -m venv .venv                          # in the repository root
.venv\Scripts\Activate.ps1                    # Linux/macOS:  source .venv/bin/activate
cd dev
pip install -r ..\requirements.txt
pip install openpyxl                          # reads the expert rating sheets (see "Shared files" below)

python -m backend.component3_soc.run_all      # EVERYTHING in one go: pipeline, evidence scripts, tests
```
Or step by step:
```
python -m backend.component3_soc.pipeline                    # score and rank all alerts -> outputs/scored_alerts.csv
python -m backend.component3_soc.service                     # live service (leave this window open)
python -m backend.component3_soc.replay_sender --limit 300   # in a 2nd window: plays Component 1's alerts
python -m streamlit run "frontend/pages/soc_ dash/app.py"     # dashboard (Component 3 SOC page)
```
Each evidence script can be run alone, for example `python -m backend.component3_soc.analysis.sensitivity`.

## How to test (from the dev folder)
```
python -m unittest discover -s backend/component3_soc/test -v
```
51 tests, about 1 minute. They check the formula against hand-calculated cases, bad inputs, the level boundaries, the
frequency window by hand, the whole batch run against the verified results (26,699 alerts; 3,642 Critical, 16,066 High,
6,991 Medium), the live service against the batch run, and that every evidence script reproduces the numbers quoted in
the presentation (weights, CR 0.031, survey-2 medians, 97.4% of gaps <= 60 s, expert agreement, parameter register),
and the incidents for Component 4 (`test_incidents.py`: 5,641 incidents, 59 s / 61 s gaps by hand, no merging across
src/dst/type, capture-wide untimed groups, max-score rule, JSON schema, same IDs on every run).

## Evidence scripts (`analysis/`) and what they prove
| Script | Reproduces | Report written to `docs/results/` |
|---|---|---|
| `ahp_survey.py` | weights and consistency ratio from survey 1 (n = 15) | `ahp_survey.txt` |
| `survey2_values.py` | severity and asset medians from survey 2 (n = 10), checked against the evidence tables | `survey2_values.txt` |
| `evidence_check.py` | that every number in `config.py` equals its evidence file, and the traffic cross-check on the raw capture | `evidence_check.txt` |
| `window_evidence.py` | why 60 s and why cap 500 | `window_evidence.txt` |
| `sensitivity.py` | what moves if one choice changes (weights +-20%, equal weights, no frequency, earlier asset values, other scaling, other cut-offs) | `sensitivity.txt` |
| `expert_validation.py` | agreement of the score with the human raters; `sheet` makes a blind sheet for a new rater | `expert_agreement.txt` |
| `parameter_register.py` | `docs/results/parameter_register.csv`: every number, its source and status | (the CSV) |

## What is committed and what is not
- Committed: code and tests, small inputs and evidence (`data/`), result reports (`docs/results/`).
- Not committed (regenerated, in `.gitignore`): `outputs/`.
- Not in the repository on purpose: the Edge-IIoTset dataset, trained models, and the surveys' free-text comments
  (removed from `survey1_ahp_responses.csv`).

## Shared files (change only through a small separate pull request)
`requirements.txt` needs `openpyxl` and `scipy` added for the evidence scripts (scikit-learn already brings scipy).

## Files
| File | Job |
|---|---|
| `config.py` | every number, with its source |
| `scoring.py` | the formula, the levels, the advice |
| `factors.py` | severity, asset, frequency |
| `calibrate.py` | honest confidence |
| `pipeline.py` | batch run |
| `service.py` | live HTTP service |
| `replay_sender.py` | demo: plays Component 1 |
| `soc_logic.py` | helpers for the dashboard page |
| `incidents.py` | groups alerts into incidents (the rule) |
| `export_incident.py` | incident.json files for Component 4 |
| `run_all.py` | runs everything above in order |
| `analysis/` | the evidence scripts |
