# Energy Plant IIoT Forensic Investigation Framework (Prototype)

Post-incident forensic analysis for energy plant (SCADA / substation) networks.
Given a confirmed incident, it joins IT logs (firewall, IDS) with OT logs (SCADA workstation,
PLC / RTU), rebuilds the attack timeline, finds the root cause and writes a forensic report.
It works offline on log files. It is rule-based: there is no model and no training data.

Component 4 of project J26-CS-328, *Explainable AI-Driven IDS and SOC Automation for Industrial IoT Security*.

## Pipeline

| Stage | What it does | Code |
|---|---|---|
| 1-2 | Load firewall, IDS and OT device logs into one schema, scope to the incident window, hash the files (SHA-256) | `log_loader.py`, `main.py` |
| 3 | Seeded IT-OT correlation: start from the attacker address in the incident and follow the attacker's actions, including pivots through compromised hosts | `correlator.py` |
| 4 | Order the correlated evidence into a stage-labelled timeline | `timeline_rca.py` |
| 5 | Root cause: initial vector, entry point, external or internal origin, compromised assets | `timeline_rca.py` |
| 6 | Charts coloured by attack stage (`theme.py`): timeline, attack flow, correlation graph, dashboard | `visualize.py` |
| 7 | Forensic report as markdown and as one HTML page with the charts embedded: header, key figures, attack-stage strip, section menu, stage / severity / source badges, light and dark themes, print layout | `report_generator.py`, `report_html.py` |

## Install

Tested on Python 3.13 (Linux) and 3.14 (Windows). The pipeline uses only the standard library. The charts need two packages:

```
pip install matplotlib networkx
```

Without them `main.py` skips the charts and still writes the report.

## Quick start

Run from the `src` folder. On Windows use `py` if `python` is not found.

```
cd src
python main.py all                        # run all 4 scenarios, reports go to output/<scenario>/
python main.py scenario1_rdp_to_breaker   # run one scenario
```

Open `output/scenario1_rdp_to_breaker/forensic_report.html` in a browser. Press Ctrl+P and
choose "Save as PDF" for a PDF.

Expected for scenario 1: 21 relevant records and 28 excluded as routine; origin external
(203.0.113.55); initial vector Initial Access; compromised hosts the workstation and the breaker PLC.

## The incident file

The pipeline starts from `data/<scenario>/incident.json`, which stands in for the confirmed-incident
handoff from the SOC component (Component 3).

```json
{
  "incident_id": "INC-2026-0910-01",
  "source_component": "SOC Alert Prioritization (Component 3)",
  "priority": "Critical",
  "seed_ips": ["203.0.113.55"],
  "window_start": "2026-09-10 08:58:00",
  "window_end": "2026-09-10 09:15:00",
  "flagged_assets": ["10.10.0.50"],
  "upstream": { "...": "optional, see below" }
}
```

Required: `seed_ips`, `window_start`, `window_end`. The format is my own proposal and has not been
agreed with Component 3.

The optional `upstream` block adds section "1b. Upstream Detection and Explanation Context" to the
report. It may hold `detection` (model, predicted_class, confidence, detected_at, alert_count),
`explanation` (method, top_features with feature / contribution / direction, summary) and
`prioritization` (priority_score, reason). Values are shown as supplied and are not verified.
Set `"illustrative_sample": true` for demonstration data. In scenarios 1 and 4 the values are
sample data, not output from the other components.

## Log formats

All three logs are CSV files with a header row.

| File | Columns |
|---|---|
| `firewall.log` | timestamp, action, src_ip, dst_ip, dst_port, protocol, label, true_stage |
| `ids_alerts.log` | timestamp, signature, severity, src_ip, dst_ip, category, label, true_stage |
| `device.log` | timestamp, device, event_type, user, description, label, true_stage |

Timestamps are `YYYY-MM-DD HH:MM:SS`. Device names end with the host address, for example
`Substation-Breaker-PLC-10.10.0.50`. The `label` and `true_stage` columns are ground truth for
scoring only; the pipeline never reads them. To use real logs, write a loader that fills the same
fields in `log_loader.py`.

## Scenarios (synthetic, with ground truth)

| Scenario | Attack |
|---|---|
| `scenario1_rdp_to_breaker` | External RDP login, brute force, malware, Modbus write to the breaker PLC |
| `scenario2_vpn_lateral_ems` | Stolen vendor VPN account, pivots to historian and EMS, IEC-104 command to a protection relay |
| `scenario3_insider_modbus` | Rogue internal device scans the OT network and writes to the PLC |
| `scenario4_c2_beacon_dnp3` | Malware on the workstation calls out to an external C2 address, spreads to the historian, DNP3 write to a relay |

`python generate_scenarios.py` recreates them.

## Evaluation scripts

All write their results to `output/`. Run from `src`.

| Command | What it does | Output file |
|---|---|---|
| `python evaluate.py` | Baseline (shared IP) against the improved method on the 4 scenarios, plus a time-window sweep | `evaluation_results.md` |
| `python heldout.py 25 2027` | 100 random scenarios from a seed (25 per template), scored against generated ground truth | `heldout_results.md` |
| `python ablation.py 25 2027` | Switches each rule off in turn and re-scores | `ablation_results.md` |
| `python benchmark.py` | Run time on 500, 5,000 and 50,000 records | `benchmark_results.md` |
| `python public_dataset_test.py <train_csv> <alerts_csv> <seed_ip>` | Runs on the Edge-IIoTset training split (file not included) | `public_dataset_results.md` |

Results from the last run (also in the progress report):

| Test | Result |
|---|---|
| 4 fixed scenarios (macro) | Precision 0.36 baseline, 1.00 improved; root cause vector 1 of 4 and 4 of 4; origin 0 of 4 and 4 of 4 |
| 100 held-out scenarios, seed 2027 | Precision 0.82, recall 1.00, F1 0.89; root cause correct in 100 of 100; baseline F1 0.23 |
| Benchmark | 0.008 s at 500 records, 0.07 s at 5,000, 0.9 s at 50,000 |
| Edge-IIoTset | F1 0.86 against 0.87 for the simple "records touching the seed address" rule |

Times depend on the computer; the other numbers are fixed by the random seeds.

## Limitations

- **Synthetic data.** The fixed and held-out scenarios, and the IDS alerts in them, are written by the
  author of the rules. Held-out scenarios were not used to tune the rules, but the generator and the
  rules share the author's assumptions, so this is a robustness test and not an independent one.
  The 4-scenario scores of 1.00 are optimistic because one rule was changed after the held-out test.
- **Routine flows from a compromised host.** A one-off routine flow from a host after it was
  compromised cannot be told apart from an attack flow by history alone. This is the cause of the
  held-out precision of 0.82. The history rule also needs earlier traffic: at 500 records precision is 0.43.
- **One seed address.** A distributed or spoofed attack from thousands of addresses cannot be reached
  from one seed. On Edge-IIoTset this left 14,254 attack records unfound. The seed must come from the
  SOC handoff; using the top source in alerts picked the victim.
- **Public dataset.** Edge-IIoTset has network records only, no date in the time field, and no
  firewall, IDS or OT device logs, so only record-level correlation could be scored there.
- **No live OT traffic.** The OT device behaviour was checked once in the OpenPLC Editor simulator.
  Suricata was not used; the IDS alerts are synthetic in a Suricata-like format.
- **Offline and rule-based.** It analyses logs after an incident. It does not detect attacks, learn
  from data, or find attack patterns its rules do not describe.
- **Handoff format not agreed.** The incident file and the `upstream` block are my proposal for the
  other components' output.

## Structure

```
data/<scenario>/   firewall.log, ids_alerts.log, device.log, incident.json, ground_truth.json
src/
  generate_scenarios.py     creates the 4 scenarios
  log_loader.py             stage 1-2   parse, normalise, scope
  correlator.py             stage 3     baseline and seeded correlation (ABLATE switches for ablation.py)
  timeline_rca.py           stage 4-5   timeline and root cause (old and current versions)
  visualize.py              stage 6     charts and dashboard
  report_generator.py       stage 7     markdown report, upstream section
  report_html.py            stage 7     single-file HTML report
  theme.py                  colours for charts and report
  pipeline.py               shared runners and scenario loader
  main.py                   run the pipeline
  evaluate.py               4-scenario evaluation
  heldout.py                random held-out test
  ablation.py               rule ablation
  benchmark.py              run-time benchmark
  public_dataset_test.py    Edge-IIoTset test
output/            reports, charts and result files
```
