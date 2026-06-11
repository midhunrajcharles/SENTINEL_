/**
 * SENTINEL — Performance Dashboard
 * performance.js
 *
 * Renders four chart panels for the /en-US/app/sentinel/performance page:
 *   1. MTTR Trend (line chart — daily average over selected range)
 *   2. Case Volume (bar chart — daily case counts, stacked by resolution)
 *   3. Detection Efficacy (bar chart — TP/FP rate per alert type)
 *   4. Cost Savings (area chart — cumulative analyst hours saved)
 *
 * Plus:
 *   - Date-range selector (24h / 7d / 30d / 90d)
 *   - Industry baseline overlay on MTTR chart
 *   - Export to CSV and PNG for each chart
 *   - Comparison numbers vs. prior period
 *
 * Dependencies: Chart.js (loaded in the page or via CDN).
 * Vanilla JS only. No frameworks.
 *
 * Splunk REST endpoints:
 *   POST /en-US/splunkd/services/search/jobs/export  (oneshot SPL searches)
 *
 * Simple XML conversion:
 *   Wrap each chart in a custom HTML panel and initialise with
 *   Perf.renderChart(chartId, range) from a SplunkJS search callback.
 */

'use strict';

/* =========================================================================
   Configuration
   ========================================================================= */

const PERF_CFG = {
  SPLUNK_BASE:  '',
  SESSION_KEY:  window.SPLUNK_SESSION_KEY || '',
  // Industry baseline MTTR in minutes (4.2 hours)
  BASELINE_MTTR_MIN: 252,
  ANALYST_HOURLY_RATE: 85,
};

const DATE_RANGES = {
  '24h': { label: '24h', earliest: '-24h', bucketSize: '1h',  displayFmt: 'HH:mm' },
  '7d':  { label: '7d',  earliest: '-7d',  bucketSize: '1d',  displayFmt: 'MMM d' },
  '30d': { label: '30d', earliest: '-30d', bucketSize: '1d',  displayFmt: 'MMM d' },
  '90d': { label: '90d', earliest: '-90d', bucketSize: '1w',  displayFmt: 'MMM d' },
};

/* Chart.js global defaults */
function applyChartDefaults() {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.color                          = '#8fa3bf';
  Chart.defaults.borderColor                    = 'rgba(255,255,255,0.06)';
  Chart.defaults.font.family                    = "'Inter', 'Segoe UI', sans-serif";
  Chart.defaults.font.size                      = 12;
  Chart.defaults.plugins.legend.labels.boxWidth = 10;
  Chart.defaults.plugins.legend.labels.padding  = 16;
}

/* =========================================================================
   State
   ========================================================================= */

const _charts = {};   // Chart.js instances keyed by id
let _activeRange = '7d';

/* =========================================================================
   SPL search helper
   ========================================================================= */

async function search(spl, earliest, latest = 'now') {
  const body = new URLSearchParams({
    search:        `search ${spl}`,
    earliest_time: earliest,
    latest_time:   latest,
    output_mode:   'json',
    count:         '1000',
  });
  const r = await fetch(`${PERF_CFG.SPLUNK_BASE}/en-US/splunkd/services/search/jobs/export`, {
    method: 'POST',
    headers: {
      'Authorization':     `Splunk ${PERF_CFG.SESSION_KEY}`,
      'X-Requested-With':  'XMLHttpRequest',
    },
    body,
  });
  if (!r.ok) return [];
  const text = await r.text();
  return text.trim().split('\n')
    .map(line => { try { return JSON.parse(line).result; } catch { return null; } })
    .filter(Boolean);
}

/* =========================================================================
   Data fetchers
   ========================================================================= */

async function fetchMttrData(range) {
  const { earliest, bucketSize } = DATE_RANGES[range];
  return search(
    `index=sentinel_metrics earliest=${earliest}
    | timechart span=${bucketSize} avg(mttr_minutes) AS avg_mttr, avg(triage_seconds) AS avg_triage,
        avg(investigation_seconds) AS avg_investigation, avg(response_seconds) AS avg_response`,
    earliest
  );
}

async function fetchVolumeData(range) {
  const { earliest, bucketSize } = DATE_RANGES[range];
  return search(
    `index=sentinel_cases status=CLOSED earliest=${earliest}
    | eval resolution_group=if(resolution="FALSE_POSITIVE","False Positive",
                           if(isnull(autonomous),"Manual","Autonomous"))
    | timechart span=${bucketSize} count AS total,
        count(eval(resolution_group="Autonomous")) AS autonomous,
        count(eval(resolution_group="False Positive")) AS false_positive,
        count(eval(resolution_group="Manual")) AS manual`,
    earliest
  );
}

async function fetchEfficacyData(range) {
  const { earliest } = DATE_RANGES[range];
  return search(
    `index=sentinel_cases status=CLOSED earliest=${earliest}
    | stats count AS total,
        sum(eval(resolution="FALSE_POSITIVE")) AS fp_count,
        sum(eval(resolution!="FALSE_POSITIVE" AND isnotnull(resolution))) AS tp_count,
        avg(mttr_minutes) AS avg_mttr
      BY alert_type
    | eval tp_rate=round(tp_count/total*100,1), fp_rate=round(fp_count/total*100,1)
    | sort -total | head 8`,
    earliest
  );
}

async function fetchSavingsData(range) {
  const { earliest, bucketSize } = DATE_RANGES[range];
  return search(
    `index=sentinel_cases status=CLOSED earliest=${earliest}
    | timechart span=${bucketSize} count AS cases_closed,
        sum(eval(1.0 * ${PERF_CFG.ANALYST_HOURLY_RATE})) AS savings_usd`,
    earliest
  );
}

async function fetchPriorPeriodComparison(range) {
  // Fetch same-length window from the prior period for delta comparison
  const windows = { '24h': '-48h', '7d': '-14d', '30d': '-60d', '90d': '-180d' };
  const priorEarliest = windows[range];
  const rows = await search(
    `index=sentinel_metrics earliest=${priorEarliest} latest=-${range}
    | stats avg(mttr_minutes) AS prior_mttr, count AS prior_total`,
    priorEarliest,
    `-${range}`,
  );
  return rows[0] || {};
}

/* =========================================================================
   Chart 1: MTTR Trend
   ========================================================================= */

async function renderMttrChart(range) {
  const [rows, prior] = await Promise.all([
    fetchMttrData(range),
    fetchPriorPeriodComparison(range),
  ]);

  const labels  = rows.map(r => formatBucketLabel(r._time || r.time, range));
  const mttr    = rows.map(r => parseFloat(r.avg_mttr || 0));
  const current_avg = mttr.length > 0 ? mttr.reduce((a, b) => a + b, 0) / mttr.length : 0;
  const prior_avg   = parseFloat(prior.prior_mttr || current_avg);
  const delta_pct   = prior_avg > 0 ? ((current_avg - prior_avg) / prior_avg * 100).toFixed(1) : 0;

  updateComparisonBlock('mttr', current_avg.toFixed(1) + ' min', delta_pct, true);

  const baseline = new Array(labels.length).fill(PERF_CFG.BASELINE_MTTR_MIN);

  destroyChart('chart-mttr');
  _charts['chart-mttr'] = new Chart(getCtx('chart-mttr'), {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label:           'SENTINEL MTTR (min)',
          data:            mttr,
          borderColor:     '#00d4ff',
          backgroundColor: 'rgba(0, 212, 255, 0.08)',
          fill:            true,
          tension:         0.4,
          pointRadius:     3,
          pointHoverRadius: 5,
          borderWidth:     2,
        },
        {
          label:           'Industry Baseline (4.2h)',
          data:            baseline,
          borderColor:     'rgba(255, 68, 68, 0.5)',
          borderDash:      [6, 4],
          backgroundColor: 'transparent',
          fill:            false,
          pointRadius:     0,
          borderWidth:     1.5,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: true },
        tooltip: {
          callbacks: {
            label: ctx => `${ctx.dataset.label}: ${ctx.parsed.y.toFixed(1)} min`,
          },
        },
      },
      scales: {
        y: {
          min: 0,
          grid: { color: 'rgba(255,255,255,0.05)' },
          ticks: { callback: v => v + 'm' },
          title: { display: true, text: 'Minutes', color: '#8fa3bf' },
        },
        x: { grid: { display: false } },
      },
    },
  });
}

/* =========================================================================
   Chart 2: Case Volume
   ========================================================================= */

async function renderVolumeChart(range) {
  const rows = await fetchVolumeData(range);

  const labels    = rows.map(r => formatBucketLabel(r._time || r.time, range));
  const auto      = rows.map(r => parseInt(r.autonomous     || 0, 10));
  const manual    = rows.map(r => parseInt(r.manual         || 0, 10));
  const fp        = rows.map(r => parseInt(r.false_positive || 0, 10));
  const totalNow  = auto.reduce((a, b) => a + b, 0) + manual.reduce((a, b) => a + b, 0) + fp.reduce((a, b) => a + b, 0);

  updateComparisonBlock('volume', totalNow + ' cases', null, null);

  destroyChart('chart-volume');
  _charts['chart-volume'] = new Chart(getCtx('chart-volume'), {
    type: 'bar',
    data: {
      labels,
      datasets: [
        { label: 'Autonomous',     data: auto,   backgroundColor: 'rgba(39, 174, 96, 0.7)',  borderRadius: 2 },
        { label: 'Manual',         data: manual, backgroundColor: 'rgba(77, 166, 255, 0.5)', borderRadius: 2 },
        { label: 'False Positive', data: fp,     backgroundColor: 'rgba(255, 68, 68, 0.45)', borderRadius: 2 },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { display: true } },
      scales: {
        x: { stacked: true, grid: { display: false } },
        y: { stacked: true, min: 0, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { precision: 0 } },
      },
    },
  });
}

/* =========================================================================
   Chart 3: Detection Efficacy
   ========================================================================= */

async function renderEfficacyChart(range) {
  const rows = await fetchEfficacyData(range);

  const labels  = rows.map(r => shortAlertType(r.alert_type || ''));
  const tpRates = rows.map(r => parseFloat(r.tp_rate || 0));
  const fpRates = rows.map(r => parseFloat(r.fp_rate || 0));

  const avgFp = fpRates.length > 0 ? fpRates.reduce((a, b) => a + b, 0) / fpRates.length : 0;
  updateComparisonBlock('efficacy', avgFp.toFixed(1) + '% FP', null, null);

  destroyChart('chart-efficacy');
  _charts['chart-efficacy'] = new Chart(getCtx('chart-efficacy'), {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label:           'TP Rate %',
          data:            tpRates,
          backgroundColor: 'rgba(39, 174, 96, 0.7)',
          borderRadius:    3,
          yAxisID:         'y',
        },
        {
          label:           'FP Rate %',
          data:            fpRates,
          backgroundColor: 'rgba(255, 68, 68, 0.55)',
          borderRadius:    3,
          yAxisID:         'y',
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: true },
        tooltip: {
          callbacks: {
            label: ctx => `${ctx.dataset.label}: ${ctx.parsed.y.toFixed(1)}%`,
          },
        },
      },
      scales: {
        x: { grid: { display: false }, ticks: { maxRotation: 30 } },
        y: {
          min: 0, max: 100,
          grid: { color: 'rgba(255,255,255,0.05)' },
          ticks: { callback: v => v + '%' },
          title: { display: true, text: 'Rate %', color: '#8fa3bf' },
        },
      },
    },
  });
}

/* =========================================================================
   Chart 4: Cost Savings
   ========================================================================= */

async function renderSavingsChart(range) {
  const rows = await fetchSavingsData(range);

  const labels   = rows.map(r => formatBucketLabel(r._time || r.time, range));
  const savings  = rows.map(r => parseFloat(r.savings_usd || 0));

  // Cumulative
  const cumulative = savings.reduce((acc, val) => {
    acc.push((acc.length > 0 ? acc[acc.length - 1] : 0) + val);
    return acc;
  }, []);

  const totalSavings = cumulative.length > 0 ? cumulative[cumulative.length - 1] : 0;
  updateComparisonBlock('savings', '$' + Math.round(totalSavings).toLocaleString(), null, null);

  destroyChart('chart-savings');
  _charts['chart-savings'] = new Chart(getCtx('chart-savings'), {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label:           'Period Savings ($)',
          data:            savings,
          borderColor:     '#27ae60',
          backgroundColor: 'rgba(39, 174, 96, 0.08)',
          fill:            true,
          tension:         0.3,
          pointRadius:     3,
          borderWidth:     2,
          yAxisID:         'y',
        },
        {
          label:           'Cumulative ($)',
          data:            cumulative,
          borderColor:     '#ffcc00',
          backgroundColor: 'transparent',
          fill:            false,
          tension:         0.3,
          pointRadius:     2,
          borderDash:      [4, 3],
          borderWidth:     1.5,
          yAxisID:         'y2',
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: true },
        tooltip: {
          callbacks: {
            label: ctx => `${ctx.dataset.label}: $${ctx.parsed.y.toLocaleString(undefined, { maximumFractionDigits: 0 })}`,
          },
        },
      },
      scales: {
        x: { grid: { display: false } },
        y: {
          position: 'left',
          grid: { color: 'rgba(255,255,255,0.05)' },
          ticks: { callback: v => '$' + (v / 1000).toFixed(0) + 'k' },
          title: { display: true, text: 'Period ($)', color: '#8fa3bf' },
        },
        y2: {
          position: 'right',
          grid: { drawOnChartArea: false },
          ticks: { callback: v => '$' + (v / 1000).toFixed(0) + 'k' },
          title: { display: true, text: 'Cumulative ($)', color: '#ffcc00' },
        },
      },
    },
  });
}

/* =========================================================================
   Render all charts
   ========================================================================= */

async function renderAll(range) {
  _activeRange = range || _activeRange;

  // Show loading state on all canvas containers
  document.querySelectorAll('.chart-panel').forEach(el => el.classList.add('loading'));

  await Promise.allSettled([
    renderMttrChart(_activeRange),
    renderVolumeChart(_activeRange),
    renderEfficacyChart(_activeRange),
    renderSavingsChart(_activeRange),
  ]);

  document.querySelectorAll('.chart-panel').forEach(el => el.classList.remove('loading'));
}

/* =========================================================================
   Date range selector
   ========================================================================= */

document.querySelectorAll('.date-range-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.date-range-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    renderAll(tab.dataset.range);
  });
});

/* =========================================================================
   Export functions
   ========================================================================= */

/** Export a chart as PNG via canvas toDataURL. */
function exportChartPNG(chartId, filename) {
  const chart = _charts[chartId];
  if (!chart) return;
  const url  = chart.toBase64Image('image/png', 1.0);
  const link = document.createElement('a');
  link.href     = url;
  link.download = filename || `SENTINEL_${chartId}_${_activeRange}.png`;
  link.click();
}

/** Export the underlying data as CSV. */
function exportChartCSV(chartId, filename) {
  const chart = _charts[chartId];
  if (!chart) return;

  const { labels, datasets } = chart.data;
  const header = ['Date', ...datasets.map(d => d.label)].join(',');
  const rows = labels.map((label, i) =>
    [label, ...datasets.map(d => d.data[i] ?? '')].join(',')
  );

  const csv  = [header, ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href     = url;
  link.download = filename || `SENTINEL_${chartId}_${_activeRange}.csv`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 3000);
}

/* =========================================================================
   Comparison blocks
   ========================================================================= */

function updateComparisonBlock(id, value, deltaPct, lowerIsBetter) {
  const valEl   = document.getElementById(`cmp-value-${id}`);
  const deltaEl = document.getElementById(`cmp-delta-${id}`);
  if (valEl)   valEl.textContent = value;
  if (deltaEl && deltaPct !== null) {
    const better = lowerIsBetter ? deltaPct < 0 : deltaPct > 0;
    const arrow  = deltaPct > 0 ? '▲' : '▼';
    deltaEl.textContent = `${arrow} ${Math.abs(deltaPct)}% vs prior period`;
    deltaEl.style.color = better ? 'var(--low)' : deltaPct === 0 ? 'var(--text-muted)' : 'var(--critical)';
  }
}

/* =========================================================================
   Helpers
   ========================================================================= */

function getCtx(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Canvas #${id} not found`);
  return el.getContext('2d');
}

function destroyChart(id) {
  if (_charts[id]) {
    _charts[id].destroy();
    delete _charts[id];
  }
}

function formatBucketLabel(timeStr, range) {
  if (!timeStr) return '';
  const d = new Date(timeStr);
  if (isNaN(d)) return timeStr;
  if (range === '24h') return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (range === '90d') return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function shortAlertType(type) {
  // RANSOMWARE_POWERSHELL_ENCODED -> Ransomware PS
  const parts = type.split('_');
  if (parts.length <= 2) return type.replace(/_/g, ' ');
  return parts[0].slice(0, 1).toUpperCase() + parts[0].slice(1).toLowerCase() + ' ' + parts[1].slice(0, 4);
}

/* =========================================================================
   Init
   ========================================================================= */

function init() {
  if (typeof Chart === 'undefined') {
    // Chart.js not yet ready — wait and retry
    setTimeout(init, 300);
    return;
  }
  applyChartDefaults();
  renderAll('7d');
}

document.addEventListener('DOMContentLoaded', init);

/* =========================================================================
   Public API
   ========================================================================= */

window.Perf = { renderAll, renderMttrChart, renderVolumeChart, renderEfficacyChart, renderSavingsChart, exportChartPNG, exportChartCSV };
