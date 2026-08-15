document.getElementById('save').addEventListener('click', async () => {
  const mode = document.getElementById('mode').value;
  const threshold = Number(document.getElementById('threshold').value);

  await chrome.storage.local.set({ sentinelaiMode: mode, sentinelaiThreshold: threshold });
  alert('SentinelAI settings saved.');
});
