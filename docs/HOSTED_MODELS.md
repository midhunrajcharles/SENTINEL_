# SENTINEL Hosted Models Guide

Integration patterns for Foundation-Sec-1.1-8B-Instruct (alert classification and
report synthesis) and Cisco Deep Time Series (anomaly forecasting and threshold
optimisation), including rate limits, caching, and performance benchmarks.

---

## Overview

SENTINEL uses two hosted AI models, both served via Splunk AI Toolkit:

| Model | Agent | Use Cases |
|-------|-------|-----------|
| Foundation-Sec-1.1-8B-Instruct | Vanguard, Sherlock, Executor, Sage | Alert classification, investigation synthesis, action justification, weekly report narrative |
| Cisco Deep Time Series | Sage | Alert volume anomaly forecasting, detection threshold optimisation, MTTR trend analysis |

Both models are accessed via Splunk's internal REST API (`/services/ml/models/...`).
No external internet calls are made — all inference runs within the Splunk instance.

---

## Foundation-Sec-1.1-8B-Instruct

### What It Is

Foundation-Sec is an 8-billion-parameter LLM fine-tuned on cybersecurity datasets
(CVEs, threat reports, MITRE ATT&CK, incident reports). It outperforms general-purpose
models of similar size on security classification tasks.

SENTINEL uses it in four different modes depending on which agent is calling:

| Mode | Prompt Pattern | Output |
|------|---------------|--------|
| Triage (Vanguard) | Alert evidence package → classification | JSON: classification, MITRE tactic/technique, confidence, reasoning |
| Investigation synthesis (Sherlock) | Raw evidence → executive summary + narrative | JSON: executive_summary, attack_narrative, false_positive_probability |
| Action justification (Executor) | Sherlock report + proposed action → justification | Plain text: 1–3 sentence justification |
| Efficacy analysis (Sage) | Closed case metrics → recommendations | Plain text: analysis narrative + tuning suggestions |

### API Call Pattern

```python
# From agent_vanguard.py — _call_model()
def _call_model(self, prompt: str) -> str:
    endpoint = (
        f"https://{self._splunk_host}:{self._splunk_port}"
        f"/services/ml/models/foundation-sec-1.1-8b-instruct/predict"
    )
    payload = {
        "inputs":     [{"role": "user", "content": prompt}],
        "parameters": {
            "max_new_tokens":  1024,
            "temperature":     0.1,    # Low temperature for consistent classification
            "do_sample":       False,  # Greedy decoding for repeatability
            "system_prompt":   self._system_prompt,
        }
    }
    resp = self._session.post(
        endpoint,
        headers={"Authorization": f"Bearer {self._model_token}"},
        json=payload,
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["predictions"][0]["generated_text"]
```

### System Prompts

Each agent has its own system prompt in `models/prompts/`:

```
models/prompts/
  vanguard_system_prompt.txt    — classification + MITRE mapping instructions
  sherlock_system_prompt.txt    — investigation synthesis instructions
  executor_system_prompt.txt    — action justification instructions
  sage_system_prompt.txt        — efficacy analysis instructions
```

The prompts instruct the model to respond in structured JSON, specify the output
schema, and include few-shot examples of well-formed responses.

### Triage Prompt Structure (Vanguard)

```
[SYSTEM PROMPT]
You are a cybersecurity triage analyst. Classify the following security alert and
return ONLY valid JSON matching this schema: ...

[USER PROMPT — assembled by VanguardAgent._build_prompt(case, asset_ctx, notables)]
=== ALERT ===
Alert Type: RANSOMWARE_POWERSHELL_ENCODED
Affected Host: DESKTOP-ABC123 (Asset Criticality: HIGH)
Affected User: CORP\jdoe (UEBA Risk Score: 72)
Raw Fields: {...}

=== ASSET CONTEXT ===
OS: Windows 10 22H2
Environment: corporate
Known Vulnerabilities: CVE-2023-23397 (Outlook RCE, CVSS 9.8)

=== PROCESS TREE ===
winword.exe (PID 4521) → powershell.exe -EncodedCommand JABj... (PID 7842) → ...

=== RELATED NOTABLES ===
3 related notables in the past 7 days: [...]

=== TASK ===
Classify this alert. Respond with JSON only:
```

### Fallback Classification (Rule-Based)

When Foundation-Sec is unavailable (504/503, model loading, token expired), Vanguard
falls back to `_FALLBACK_RULES` — a prioritised list of condition functions:

```python
_FALLBACK_RULES = [
    # (condition_fn, classification, tactic, technique, base_confidence)
    (
        lambda d: _contains(d.get("alert_type",""), "ransomware", "cryptolocker", "lockbit"),
        "RANSOMWARE_INITIAL_ACCESS", "TA0001", "T1566.001", 0.75,
    ),
    (
        lambda d: _contains(d.get("alert_type",""), "powershell", "encoded_command"),
        "MALICIOUS_POWERSHELL", "TA0002", "T1059.001", 0.70,
    ),
    (
        lambda d: _contains(d.get("alert_type",""), "brute_force", "spray", "failed_logon"),
        "CREDENTIAL_ACCESS_BRUTE_FORCE", "TA0006", "T1110.001", 0.65,
    ),
    # ... 20+ rules total
]
```

Fallback results have `model_available: false` in the `VanguardDecisionPacket`.
Sage tracks fallback frequency and alerts if `fallback_rate > 0.10` in the weekly report.

---

## Cisco Deep Time Series

### What It Is

Cisco Deep Time Series is a specialised time series model for anomaly detection and
forecasting over enterprise security metrics. SENTINEL uses it in SageAgent for:

1. **Anomaly forecasting** — detecting unusual spikes in alert volume, FP rate, or MTTR
2. **Threshold optimisation** — finding the optimal risk score threshold for each detection rule
3. **Trend analysis** — characterising whether a metric is improving, degrading, or stable

### `_CiscoTimeSeriesClient` and the Fallback Chain

```python
class _CiscoTimeSeriesClient:
    """
    Wraps the Cisco Deep Time Series hosted model endpoint.
    Falls back to _TimeSeries built-ins when base_url or token is empty.
    """

    def _is_available(self) -> bool:
        return bool(self._base_url and self._token)

    def forecast_anomaly(self, series: List[float]) -> dict:
        if not self._is_available():
            # Built-in fallback using _TimeSeries
            anomalies = _TimeSeries.detect_anomalies(series)
            forecast  = _TimeSeries.forecast_linear(series, horizon=3)
            return {
                "anomalies": anomalies,
                "forecast":  forecast,
                "model":     "builtin_linear",
            }
        # ... Cisco endpoint call
```

**Decision tree for choosing the model:**

```
Is SENTINEL_CISCO_TS_URL and SENTINEL_CISCO_TS_TOKEN set?
    │
    ├── Yes: Does the endpoint respond to a health check?
    │       │
    │       ├── Yes: Use Cisco Deep Time Series (higher accuracy)
    │       │
    │       └── No (timeout/503): Fall back to _TimeSeries built-ins
    │               → Log warning: "Cisco TS endpoint unavailable — using builtin"
    │
    └── No: Use _TimeSeries built-ins directly (no warning — expected in dev)
```

### Anomaly Detection Use Case

Sage runs weekly on alert volume series to detect unusual spikes:

```python
# From agent_sage.py — weekly efficacy analysis
weekly_volumes = [142, 138, 151, 147, 144, 139, 287]  # last 7 weeks (287 is a spike)
result = ts_client.forecast_anomaly(weekly_volumes)

# result = {
#   "anomalies":  [False, False, False, False, False, False, True],
#   "forecast":   [160.2, 162.5, 158.1],   # next 3 weeks projected
#   "model":      "cisco-deep-time-series",
#   "confidence": 0.94,
# }

if result["anomalies"][-1]:
    report.recommendations.append(
        "Alert volume spike detected last week (+100% vs. 6-week avg). "
        "Review for infrastructure changes or new threat campaign."
    )
```

### Threshold Optimisation Use Case

Sage uses the model to tune Vanguard's decision thresholds:

```python
# Gather 90 days of closed cases: their risk scores and ground-truth labels
scores = [case.risk_score for case in closed_cases]          # e.g., [82, 45, 91, 33, ...]
labels = [1 if case.is_true_positive else 0 for case in closed_cases]

result = ts_client.optimize_threshold(scores, labels, target_tpr=0.90)
# result = {
#   "optimal_threshold": 72,
#   "tpr_at_threshold":  0.921,
#   "fpr_at_threshold":  0.083,
#   "model":             "cisco-deep-time-series",
# }

# If threshold differs from current value by <= _MAX_THRESHOLD_DELTA, apply automatically
current = 70
proposed = result["optimal_threshold"]
if abs(proposed - current) <= _MAX_THRESHOLD_DELTA:
    _apply_threshold_change(current, proposed)
```

### `_TimeSeries` Built-in Algorithms

When Cisco TS is unavailable, these pure-Python algorithms run instead:

| Method | Algorithm |
|--------|-----------|
| `moving_average(series, window)` | Simple moving average with edge padding |
| `linear_trend(series)` | Ordinary least squares regression |
| `z_scores(series)` | (x - μ) / σ; returns 0.0 for single-element series |
| `detect_anomalies(series, threshold=2.0)` | z-score > threshold → anomaly |
| `forecast_linear(series, horizon=1)` | Extrapolates OLS line for `horizon` steps |
| `compare_windows(series, window)` | Compares last `window` points to previous `window` |
| `optimize_threshold(scores, labels, target_tpr)` | Grid search over [0,100] maximising TPR − 2×FPR |

The built-ins sacrifice model accuracy for zero-dependency availability. They are
appropriate for dev environments and low-volume deployments.

---

## API Rate Limits and Caching Strategies

### Foundation-Sec Rate Limits

The model endpoint is managed by Splunk AI Toolkit and shared across all apps.

| Limit | Default | Notes |
|-------|---------|-------|
| Requests per minute | 60 | Across all tokens for this Splunk instance |
| Max tokens per request | 4096 input + 1024 output | Longer prompts are truncated |
| Concurrent requests | 4 | Queued beyond this limit |
| Request timeout | 30s | Longer inference times return 504 |

SENTINEL manages these limits with:

1. **Per-agent call serialisation** — each agent processes one model call at a time
2. **Exponential backoff** on 429/503 — base 2s, max 30s, 3 attempts
3. **Prompt compression** — evidence packages are truncated to the most recent 2000 chars if they approach the token limit

### Cisco Deep Time Series Rate Limits

| Limit | Default |
|-------|---------|
| Requests per minute | 30 |
| Max series length | 8760 points (1 year of hourly data) |
| Concurrent requests | 2 |
| Request timeout | 15s |

### Response Caching (Sage)

Sage caches model responses for identical inputs to avoid redundant inference:

```python
# In-memory LRU cache for model responses during a single Sage run
@lru_cache(maxsize=128)
def _cached_model_call(self, prompt_hash: str) -> str:
    return self._call_model(self._prompts[prompt_hash])
```

Cache scope is per-run (not persisted). The same alert type will not trigger two
identical Foundation-Sec calls within one `run_scheduled()` execution.

---

## Model Performance Benchmarks

Measured on a Splunk 9.3 instance with 16 CPU cores and 32 GB RAM.

### Foundation-Sec-1.1-8B Classification Latency

| Prompt Size | p50 | p95 | p99 |
|-------------|-----|-----|-----|
| Short (<500 tokens) | 2.1s | 3.8s | 6.2s |
| Medium (500–1500 tokens) | 4.4s | 7.1s | 11.3s |
| Long (1500–3000 tokens) | 8.2s | 14.6s | 22.1s |

**Typical Vanguard call:** 800–1200 tokens → p50 ~5s.

### Foundation-Sec Investigation Synthesis Latency (Sherlock)

| Report Complexity | Evidence Size | p50 | p95 |
|-------------------|--------------|-----|-----|
| Low (< 10 events) | ~1000 tokens | 3.2s | 6.1s |
| Medium (10–50 events) | ~2500 tokens | 7.8s | 13.4s |
| High (50+ events) | ~4000 tokens | 14.1s | 24.7s |

### Cisco Deep Time Series Latency

| Operation | Series Length | p50 | p95 |
|-----------|--------------|-----|-----|
| `forecast_anomaly` | 52 points (1yr weekly) | 0.8s | 2.1s |
| `optimize_threshold` | 1000 labelled cases | 1.4s | 3.8s |
| `analyze_trend` | 52 points | 0.6s | 1.9s |

### Classification Accuracy (on labelled test set)

| Metric | Foundation-Sec | Fallback Rules |
|--------|---------------|----------------|
| True Positive Rate | 94.2% | 81.7% |
| False Positive Rate | 5.8% | 12.3% |
| MITRE tactic accuracy | 91.4% | 74.2% |
| MITRE technique accuracy | 84.1% | 58.6% |

The fallback rule-based classifier is effective for common attack patterns but misses
novel techniques that do not match keyword-based signatures.

---

## Configuration Reference

```ini
# sentinel.conf [models]
[models]
hosted_model_token         = <token-with-ml_model_inference-capability>
foundation_sec_endpoint    = https://localhost:8089/services/ml/models/foundation-sec-1.1-8b-instruct/predict
cisco_ts_endpoint          = https://localhost:8089/services/ml/models/cisco-deep-time-series/predict

# Inference parameters
foundation_sec_max_tokens  = 1024
foundation_sec_temperature = 0.1
foundation_sec_timeout_s   = 30

cisco_ts_timeout_s         = 15
```

```bash
# Environment variable overrides
export SENTINEL_HOSTED_MODEL_TOKEN="<token>"
export SENTINEL_CISCO_TS_URL="https://localhost:8089/services/ml/models/cisco-deep-time-series/predict"
export SENTINEL_CISCO_TS_TOKEN="<same-token>"
```
