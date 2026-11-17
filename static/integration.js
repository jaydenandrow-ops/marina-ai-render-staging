function csrfHeaders(headers = {}) { const match = document.cookie.match(/(?:^|; )__Host-marina_csrf=([^;]+)/); if (match) headers['X-Marina-CSRF'] = decodeURIComponent(match[1]); return headers; }
(() => {
  const $ = (s) => document.querySelector(s);
  const memoryToggle = $('#useMemories');
  const contextConsent = $('#cloudContextConsentWrap');
  const contextCheckbox = $('#shareConversationContext');
  let cloudAvailable = false;
  let routedSinhala = false;

  function looksLikeSinhalaOrSinglish(text) {
    return /[\u0D80-\u0DFF]/.test(text) ||
      /\b(oya|oyaa|oyata|mata|sinhala|puluwanda|kawda|kauda|bohoma|istuti|kohomada|udaw|karanna|mokakda)\b/i.test(text);
  }

  function updateProviderNotice() {
    const language = $('#languageSelect').value;
    const languageWarning = language === 'si' || (language === 'auto' &&
      (routedSinhala || looksLikeSinhalaOrSinglish($('#messageInput').value)));
    const base = cloudAvailable
      ? `AI responses are powered by OpenAI. Your current message and system instructions are sent to OpenAI. Recent turns are included only when you enable sharing; saved memories stay local. API use may incur charges.`
      : 'The AI service is unavailable right now. Check the local configuration.';
    $('#providerNotice').textContent = languageWarning
      ? `${base} Sinhala and Singlish quality can vary; verify important details.` : base;
    $('#providerNotice').classList.toggle('language-warning', languageWarning);
    memoryToggle.disabled = true;
    memoryToggle.title = 'Saved memories are local and are not sent to OpenAI.';
    contextConsent.hidden = !cloudAvailable;
  }

  async function loadProviderStatus() {
    try {
      const response = await fetch('/api/providers');
      const data = await response.json();
      cloudAvailable = Boolean(data.providers?.openai?.available);
      if (!cloudAvailable) contextCheckbox.checked = false;
      updateProviderNotice();
    } catch {
      cloudAvailable = false;
      contextCheckbox.checked = false;
      updateProviderNotice();
    }
  }

  $('#languageSelect').addEventListener('change', () => {
    routedSinhala = false;
    updateProviderNotice();
  });
  $('#messageInput').addEventListener('input', () => {
    if ($('#messageInput').value.trim()) routedSinhala = false;
    updateProviderNotice();
  });
  document.addEventListener('genesis:language', (event) => {
    routedSinhala = event.detail === 'si';
    updateProviderNotice();
  });

  $('#memoryButton').addEventListener('click', () => {
    $('#memoryOverlay').hidden = false;
    $('#memoryError').textContent = '';
    loadMemories();
  });
  $('#closeMemories').addEventListener('click', () => { $('#memoryOverlay').hidden = true; });
  $('#memoryOverlay').addEventListener('click', (e) => {
    if (e.target.id === 'memoryOverlay') e.currentTarget.hidden = true;
  });

  async function loadMemories() {
    const target = $('#memoryList');
    target.replaceChildren();
    try {
      const response = await fetch('/api/memories');
      const data = await response.json();
      if (!response.ok) throw Error(data.detail || 'Could not load saved memories.');
      for (const memory of data.memories) {
        const item = document.createElement('div');
        item.className = 'memory-item';
        const text = document.createElement('span');
        text.textContent = memory.content;
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.textContent = 'Delete';
        remove.addEventListener('click', async () => {
          const result = await fetch(`/api/memories/${memory.id}`, { method: 'DELETE', headers: csrfHeaders({}) });
          if (result.ok) loadMemories();
          else $('#memoryError').textContent = 'Could not delete this memory.';
        });
        item.append(text, remove);
        target.append(item);
      }
      if (!data.memories.length) target.textContent = 'No approved memories saved.';
    } catch (error) {
      $('#memoryError').textContent = error.message || 'Could not load saved memories.';
    }
  }

  function updateSaveButton() {
    $('#saveMemory').disabled = !$('#memoryConsent').checked || !$('#memoryInput').value.trim();
  }
  $('#memoryConsent').addEventListener('change', updateSaveButton);
  $('#memoryInput').addEventListener('input', updateSaveButton);
  $('#saveMemory').addEventListener('click', async () => {
    const button = $('#saveMemory');
    button.disabled = true;
    $('#memoryError').textContent = '';
    try {
      const response = await fetch('/api/memories', {
        method: 'POST', headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ consent: $('#memoryConsent').checked, content: $('#memoryInput').value }),
      });
      const result = await response.json();
      if (!response.ok) throw Error(result.detail || 'Could not save memory.');
      $('#memoryInput').value = '';
      $('#memoryConsent').checked = false;
      await loadMemories();
    } catch (error) {
      $('#memoryError').textContent = error.message || 'Could not save memory.';
    } finally {
      updateSaveButton();
    }
  });

  memoryToggle.checked = false;

  $('#loadResearchDashboard').addEventListener('click', async () => {
    const out = $('#researchDashboard');
    out.textContent = 'Loading archived research results…';
    try {
      const response = await fetch('/api/research/dashboard');
      const data = await response.json();
      if (!response.ok) throw Error(data.detail || 'Dashboard unavailable.');
      out.textContent = JSON.stringify(data, null, 2);
    } catch (error) {
      out.textContent = error.message || 'Could not load archived results.';
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') $('#memoryOverlay').hidden = true;
  });
  loadProviderStatus().then(loadModels).then(updateProviderNotice);
  updateProviderNotice();
})();
