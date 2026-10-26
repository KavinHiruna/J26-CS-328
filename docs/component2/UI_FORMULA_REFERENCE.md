# Formula Reference for Web Injection and Flood Detection UIs

## Purpose and scope

This reference collects the formulas discussed for the Web Injection, DDoS HTTP Flood, and Network Flood interfaces. It distinguishes formulas visible in the supplied DDoS screenshots from standard formulas that may be used by the other pages but still need confirmation against their source code. A formula marked **Verify in code** should not be presented as a confirmed implementation until the relevant Streamlit page is inspected.

The user interface combines three kinds of values: packet or flow measurements, classifier outputs, and model-explanation values. They have different meanings. In particular, a model probability is not a traffic percentage, and an explanation contribution is not a percentage of packets.

## Shared classifier and explanation formulas

### Random Forest class probability

For (T) trees, the ensemble probability for class (c) is commonly calculated as:

\[
P(c\mid x)=\frac{1}{T}\sum_{t=1}^{T}P_t(c\mid x)
\]

Here, (x) is one packet or flow and (P_t) is tree (t)'s class probability. The UI displays the probability for the attack class, for example (P(\text{HTTP flood}\mid x)=0.992\), or 99.2%.

### Thresholded prediction

\[
\hat y=\begin{cases}
1 & P(\text{attack}\mid x)\geq\tau\\
0 & P(\text{attack}\mid x)<\tau
\end{cases}
\]

The screenshots show a threshold of 0.50 in the HTTP Flood view. Confirm the threshold separately for Web Injection and Network Flood.

### Feature contributions

For additive explanations such as the SHAP chart shown in the screenshots:

\[
f(x)\approx f_{base}+\sum_{i=1}^{m}\phi_i
\]

The baseline is the reference model output; \(\phi_i\) is feature (i)'s contribution for this record. Positive contributions push toward the class being explained; negative contributions push away. If the output is displayed as percentage points, multiply a probability-scale contribution by 100. Contributions should not be interpreted as causal effects.

The Web Injection incident screenshot describes **Tree-path contributions (Saabas)**. Saabas contributions are computed along decision paths and can depend on feature order; do not label them exact SHAP values unless the code actually calls a SHAP method.

### Local explanation with LIME

LIME perturbs an instance, weights the perturbed samples by proximity to the original instance, then fits a simpler local surrogate model. Its displayed weights are surrogate-model coefficients or contributions. There is no single universal closed-form equation for the displayed weight: it depends on the perturbation, distance kernel, feature representation, and fitted surrogate. Label these as **local approximation weights**, not Random Forest coefficients.

### Global feature importance

A common SHAP global-importance summary is mean absolute contribution:

\[
I_i=\frac{1}{N}\sum_{j=1}^{N}|\phi_{ij}|
\]

It describes average contribution magnitude over (N) records, without indicating whether the feature pushes toward attack or normal.

## Web Injection UI

The exact Web Injection page source was not available while preparing this reference. The formulas below are therefore the shared model/XAI formulas above, plus common traffic measures that should be included only if the page displays them.

### Common traffic measures to verify

For a selected time window with duration \(\Delta t\):

| Measure | Formula | Interpretation |
|---|---|---|
| Request rate | \(N_{requests}/\Delta t\) | Requests per second, minute, or other stated interval. |
| Flagged share | \(N_{flagged}/N_{total}\times100\) | Fraction of records flagged by the model. |
| Unique sources | \(|\{source\ IP\}|\) | Count of distinct source IPs, not a rate. |
| URI flagged share | \(N_{flagged,URI}/N_{all,URI}\times100\) | Flagged portion of requests for a URI. |

For injection-specific labels such as SQL injection or XSS, the attack probability is still a model output. Payload or URI strings are observed feature values unless the code explicitly derives a count, pattern flag, or other transformation from them.

## DDoS HTTP Flood UI

The following values are visible in the supplied HTTP Flood screenshots.

### Incident and source-level values

| UI value | Formula or definition |
|---|---|
| Attack probability | Random Forest probability (P(HTTP\ flood\mid x)\), displayed as a percentage. |
| Same request | Count from the selected source matching the incident's request method and URL. The screenshot reports 201. |
| Requests \(\pm60s\) | Count for the source within 60 seconds before and after the incident. This is a 120-second window. The screenshot reports 438. |
| Approximate requests/minute | (438/120\times60=219\) requests/minute for that example. |
| Flagged share \(\pm60s\) | (N_{flagged,window}/N_{source,window}\times100\). The screenshot reports 75%. |
| Flagged traffic share | (5,759/126,240\times100\approx4.6\%\) for the Live Detection screenshot. |
| URI flagged share | (N_{flagged,URI}/N_{requests,URI}\times100\). The profile table displays this as a percentage. |
| Sources per URI | Number of distinct source IPs observed for that URI. |

The requests-per-URI timeline bins requests by time and URI. Its screenshot says the dataset is a sample and rates are approximate; do not treat those chart rates as exact full-capture rates.

### XAI consensus and faithfulness

The consensus banner in the supplied screenshots gives:

\[
XCS=0.33R+0.33K+0.33D
\]

where (R) is rank agreement, (K) is top-k feature overlap, and (D) is contribution-direction agreement. This formula is confirmed for the displayed consensus component; the exact calculations of (R), (K), and (D) should be checked in code.

The screenshot defines faithfulness as:

\[
\Delta_{top-k}=P(x)-P(x\ without\ top-k\ features)
\]

It compares this drop with a random-feature removal drop. A larger top-k drop suggests the selected explanatory features have greater influence on the model output than the random features in that test. It does not establish that the prediction is factually correct.

### Performance metrics

Using (TP) = attack records correctly flagged, (TN) = normal records correctly left unflagged, (FP) = normal records incorrectly flagged, and (FN) = attacks missed:

| Metric | Formula |
|---|---|
| Accuracy | \((TP+TN)/(TP+TN+FP+FN)\) |
| Precision | \(TP/(TP+FP)\) |
| Recall / true positive rate | \(TP/(TP+FN)\) |
| Specificity / true negative rate | \(TN/(TN+FP)\) |
| False positive rate | \(FP/(FP+TN)=1-specificity\) |
| False negative rate | \(FN/(FN+TP)=1-recall\) |
| F1 score | \(2\times precision\times recall/(precision+recall)\) |
| Balanced accuracy | \((recall+specificity)/2\) |
| ROC-AUC | Area under the ROC curve of TPR versus FPR over thresholds. |

## Network Flood UI

The exact Network Flood page source was not available while preparing this reference. These are standard derived network measurements, not verified claims about every feature in that UI.

For packets in one flow or time window, let (N) be the packet count, (B_i) each packet's byte length, and (t_i) packet timestamps.

| Feature | Common formula | Unit or note |
|---|---|---|
| Flow duration | \(t_{last}-t_{first}\) | Seconds. |
| Packet rate | \(N/\Delta t\) | Packets per second. |
| Byte rate | \(\sum_iB_i/\Delta t\) | Bytes per second. Multiply by 8 for bits per second. |
| Average packet size | \(\sum_iB_i/N\) | Bytes per packet. |
| Mean inter-arrival time | \(\frac{1}{N-1}\sum_{i=2}^{N}(t_i-t_{i-1})\) | Seconds; requires ordered timestamps and (N>1). |
| Inter-arrival variability | \(\sigma_{IAT}/\mu_{IAT}\) | Coefficient of variation; undefined if mean is zero. |
| Flagged share | \(N_{flagged}/N_{total}\times100\) | Percentage for the selected window. |
| Unique source/destination count | Number of distinct IP values | Count, not percentage. |
| Protocol share | \(N_{protocol}/N_{total}\times100\) | Percentage of packets using a protocol. |
| TCP SYN ratio | \(N_{SYN-only}/N_{TCP}\) | Ratio in a window; define SYN-only consistently and handle zero TCP packets. |
| Source concentration | \(N_{packets,top\ source}/N_{total}\) | Share of packets from the busiest source. |
| Address/port entropy | \(-\sum_i p_i\log_2p_i\) | (p_i) is the observed share of address or port (i); requires a defined category set. |

Fields such as source IP, destination IP, ports, protocol, and TCP flags are often read directly from packet data rather than calculated. Their presence as a model feature does not imply a derived formula.

## Formula interpretation and verification checklist

1. Confirm the exact source file and code block for each UI card or chart.
2. Confirm units and window boundaries: packets/second versus packets/minute, and whether a window is total length \(\Delta t\) or a symmetric \(\pm w\) interval of length (2w).
3. Confirm denominator and missing-value rules. Percentages are undefined when their denominator is zero.
4. Confirm which target class a probability or explanation refers to.
5. Confirm whether contribution values are probability units, percentage points, or normalized display values.
6. Treat dataset labels and model outputs separately. Agreement with labels measures consistency with those labels, not necessarily real-world ground truth.

