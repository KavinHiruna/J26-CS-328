# Interface contract (agree once, then do not change without telling everyone)

## C1 -> C2 and C3: detection alert  (JSON, one per network flow)
```json
{"flow_id": 1042, "src_ip": "192.168.0.170", "dst_ip": "192.168.0.128",
 "predicted_type": "Ransomware", "confidence": 0.97, "event_time": 61234.5,
 "features": {"tcp.flags": 2, "...": 0}}
```
- `predicted_type`: one of the 15 Edge-IIoTset classes (Normal, Backdoor, DDoS_HTTP, DDoS_ICMP, DDoS_TCP, DDoS_UDP,
  Fingerprinting, MITM, Password, Port_Scanning, Ransomware, SQL_injection, Uploading, Vulnerability_scanner, XSS).
- `confidence`: calibrated probability 0-1 (C1 provides; C3 currently calibrates the XGBoost output itself).
- `event_time`: seconds, optional. `features` is optional (needed by C2).

## C2 -> C3 and C4: explanation
```json
{"flow_id": 1042, "top_features": [{"name": "http.request.method", "shap": 0.31}], "summary": "text"}
```

## C3 -> frontend and C4: prioritised incident
```json
{"alert_id": "FLOW-1042", "risk_score": 90.6, "priority": "Critical", "asset_id": "OT-001",
 "predicted_type": "Ransomware", "recommendations": ["..."]}
```
C3 service: `POST http://127.0.0.1:8765/alert` (see backend/component3_soc/README.md).

## C4: reads incidents above and builds the forensic timeline per incident.
