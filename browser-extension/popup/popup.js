const resultBox = document.getElementById('resultBox');
const resultUrl = document.getElementById('resultUrl');
const resultAction = document.getElementById('resultAction');
const resultTrust = document.getElementById('resultTrust');
const resultConfidence = document.getElementById('resultConfidence');
const resultThreat = document.getElementById('resultThreat');
const resultEvidence = document.getElementById('resultEvidence');
const resultStage = document.getElementById('resultStage');
const resultCertainty = document.getElementById('resultCertainty');
const resultTiming = document.getElementById('resultTiming');

const renderResult = (data, meta) => {
  if (!data) {
    resultBox.classList.remove('visible');
    return;
  }

  const trust = data.trust_profile?.overall ?? 0;
  const action = data.decision?.action ?? 'unknown';
  const confidence = data.decision?.confidence ?? 0;
  const threat = data.evidence?.threat_category ?? 'unknown';
  const evidence = data.evidence?.supporting_evidence?.join(', ') || 'none';
  const stage = data.decision?.stage ?? 1;
  const certainty = data.decision?.certainty ?? 'unknown';
  const mlProb = data.decision?.ml_probability;
  const timing = data.timing_ms;

  resultUrl.textContent = data.evidence?.url || 'unknown';
  resultAction.textContent = action;
  resultAction.className = action === 'block' ? 'danger' : action === 'warn' ? 'warn' : 'action';
  resultTrust.textContent = `${trust.toFixed(3)} / 1.0`;
  resultConfidence.textContent = `${confidence.toFixed(2)} / 1.0`
    + (mlProb != null ? `  (ML ${mlProb.toFixed(2)})` : '');
  resultThreat.textContent = threat;
  resultEvidence.textContent = evidence;
  resultStage.textContent = `${stage}${meta?.cached ? ' (cached)' : ''}`
    + (data.decision?.needs_deep_analysis ? ' + deep-analysis' : '');
  resultCertainty.textContent = certainty
    + (data.trust_profile?.uncertainty ? ' / uncertain' : '');
  if (timing) {
    const total = timing.total_ms ?? timing.roundtrip_ms ?? 0;
    resultTiming.textContent = `${Number(total).toFixed(1)} ms (backend${' evidence=' + timing.evidence_build + ' trust=' + timing.trust_fusion})`;
  } else {
    resultTiming.textContent = 'n/a';
  }
  resultBox.classList.add('visible');
};

document.getElementById('analyze').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  let ctx;
  try {
    ctx = await chrome.tabs.sendMessage(tab.id, { type: 'GET_PAGE_CONTEXT' });
  } catch (e) {
    ctx = {};
  }
  chrome.runtime.sendMessage({
    type: 'ANALYZE',
    payload: { url: tab.url, metadata: ctx },
  }, (response) => {
    if (response && response.ok && response.data) {
      renderResult(response.data, { cached: response.cached });
    } else {
      resultBox.classList.remove('visible');
      resultEvidence.textContent = response?.data?.error || 'Backend unavailable';
      resultBox.classList.add('visible');
    }
  });
});