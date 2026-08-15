const resultBox = document.getElementById('resultBox');
const resultUrl = document.getElementById('resultUrl');
const resultAction = document.getElementById('resultAction');
const resultTrust = document.getElementById('resultTrust');
const resultConfidence = document.getElementById('resultConfidence');
const resultThreat = document.getElementById('resultThreat');
const resultEvidence = document.getElementById('resultEvidence');

const renderResult = (data) => {
  if (!data) {
    resultBox.classList.remove('visible');
    return;
  }

  const trust = data.trust_profile?.overall ?? 0;
  const action = data.decision?.action ?? 'unknown';
  const confidence = data.decision?.confidence ?? 0;
  const threat = data.evidence?.threat_category ?? 'unknown';
  const evidence = data.evidence?.supporting_evidence?.join(', ') || 'none';

  resultUrl.textContent = data.evidence?.url || 'unknown';
  resultAction.textContent = action;
  resultAction.className = action === 'block' ? 'danger' : action === 'warn' ? 'warn' : 'action';
  resultTrust.textContent = `${trust.toFixed(3)} / 1.0`;
  resultConfidence.textContent = `${confidence.toFixed(2)} / 1.0`;
  resultThreat.textContent = threat;
  resultEvidence.textContent = evidence;
  resultBox.classList.add('visible');
};

document.getElementById('analyze').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  try {
    const pageContext = await chrome.tabs.sendMessage(tab.id, { type: 'GET_PAGE_CONTEXT' });
    chrome.runtime.sendMessage({
      type: 'ANALYZE',
      payload: { url: tab.url, metadata: pageContext }
    }, (response) => {
      if (response && response.ok && response.data) {
        renderResult(response.data);
      } else {
        resultBox.classList.remove('visible');
        resultEvidence.textContent = response?.data?.error || 'Backend unavailable';
        resultBox.classList.add('visible');
      }
    });
  } catch (error) {
    chrome.runtime.sendMessage({
      type: 'ANALYZE',
      payload: { url: tab.url, metadata: {} }
    }, (response) => {
      if (response && response.ok && response.data) {
        renderResult(response.data);
      } else {
        resultBox.classList.remove('visible');
        resultEvidence.textContent = 'Unable to inspect page content';
        resultBox.classList.add('visible');
      }
    });
  }
});
