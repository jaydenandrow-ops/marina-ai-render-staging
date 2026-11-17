(() => {
  const $ = (selector) => document.querySelector(selector);
  const button = $('#generateImageButton');
  const overlay = $('#imageOverlay');
  const consent = $('#imageCostConsent');
  const confirmButton = $('#confirmImageGeneration');
  const promptInput = $('#messageInput');
  const results = $('#imageResults');
  let imageStatus = null;
  let csrfToken = '';
  let pendingPrompt = '';
  let lastPrompt = '';
  let requestInFlight = false;

  function setFeatureStatus(text) {
    $('#imageFeatureStatus').textContent = text;
  }

  function updateConfirmation() {
    const validPrompt = pendingPrompt.trim().length > 0 && pendingPrompt.trim().length <= 2000;
    confirmButton.disabled = !consent.checked || !validPrompt || requestInFlight || !imageStatus?.available;
  }

  function formatDisclosure() {
    const cost = imageStatus?.cost;
    if (!cost) return 'Estimated cost is unavailable. Do not continue until pricing can be shown.';
    const amount = Number(cost.illustrative_output_cost_usd).toFixed(5);
    return `Illustrative official calculator example: $${amount} for ${cost.illustrative_output_tokens} image-output tokens, plus prompt text input at $${cost.text_input_usd_per_million_tokens}/million tokens. This is not a quote for the selected settings or a spending cap; actual usage may cost more. `;
  }

  function openDialog(prompt) {
    if (!imageStatus?.available) return;
    pendingPrompt = prompt;
    $('#imagePromptPreview').textContent = prompt;
    const disclosure = $('#imageCostDisclosure');
    disclosure.replaceChildren();
    const disclosureText = formatDisclosure();
    disclosure.append(document.createTextNode(disclosureText));
    const pricingLink = document.createElement('a');
    pricingLink.href = 'https://developers.openai.com/api/docs/guides/image-generation';
    pricingLink.target = '_blank';
    pricingLink.rel = 'noopener noreferrer';
    pricingLink.textContent = 'Pricing details';
    disclosure.append(pricingLink, document.createTextNode('.'));
    consent.checked = false;
    $('#imageDialogError').textContent = '';
    if (pendingPrompt.trim().length > 2000) $('#imageDialogError').textContent = 'Prompt must contain no more than 2,000 characters.';
    overlay.hidden = false;
    updateConfirmation();
    $('#imageSize').focus();
  }

  function closeDialog() {
    if (requestInFlight) return;
    overlay.hidden = true;
    pendingPrompt = '';
    consent.checked = false;
    confirmButton.disabled = true;
  }

  async function loadStatus() {
    try {
      const response = await fetch('/api/images/status', { credentials: 'same-origin', cache: 'no-store' });
      const data = await response.json();
      if (!response.ok) throw new Error('status');
      imageStatus = data;
      csrfToken = data.csrf_token || '';
      button.disabled = !data.available || !csrfToken;
      button.title = data.available
        ? 'Send only the current prompt to the configured image model.'
        : `Image generation unavailable: ${data.reason || 'disabled'}.`;
      setFeatureStatus(data.available ? 'OPTIONAL · CLOUD' : 'DISABLED');
    } catch {
      imageStatus = null;
      csrfToken = '';
      button.disabled = true;
      button.title = 'Image generation status is unavailable.';
      setFeatureStatus('UNAVAILABLE');
    }
  }

  function showImageResult(result) {
    results.replaceChildren();
    const card = document.createElement('article');
    card.className = 'image-result-card';
    const heading = document.createElement('h2');
    heading.textContent = 'Generated image';
    const details = document.createElement('p');
    const usage = result.token_usage
      ? ` · Usage: ${JSON.stringify(result.token_usage)}`
      : ' · Provider did not return token usage.';
    details.textContent = `${result.model} · ${result.size} · ${result.quality} · ${result.output_format.toUpperCase()} · ${result.width} × ${result.height} · Illustrative output estimate $${Number(result.estimated_cost_usd).toFixed(5)}${usage}`;
    const image = document.createElement('img');
    image.alt = 'Generated image preview';
    image.loading = 'lazy';
    image.src = result.preview_url;
    const actions = document.createElement('div');
    actions.className = 'image-result-actions';
    const download = document.createElement('a');
    download.href = result.download_url;
    download.textContent = 'Download image';
    download.setAttribute('download', '');
    const regenerate = document.createElement('button');
    regenerate.type = 'button';
    regenerate.textContent = 'Regenerate';
    regenerate.addEventListener('click', () => openDialog(lastPrompt));
    actions.append(download, regenerate);
    card.append(heading, details, image, actions);
    results.append(card);
    results.hidden = false;
    results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  button.addEventListener('click', () => {
    if (promptInput.disabled) return;
    const prompt = promptInput.value.trim();
    if (!prompt) {
      $('#toast').textContent = 'Write an image prompt first.';
      $('#toast').classList.add('show');
      setTimeout(() => $('#toast').classList.remove('show'), 2200);
      promptInput.focus();
      return;
    }
    openDialog(prompt);
  });
  consent.addEventListener('change', updateConfirmation);
  $('#imageSize').addEventListener('change', updateConfirmation);
  $('#imageQuality').addEventListener('change', updateConfirmation);
  $('#imageFormat').addEventListener('change', updateConfirmation);
  $('#closeImageDialog').addEventListener('click', closeDialog);
  $('#cancelImageGeneration').addEventListener('click', closeDialog);
  overlay.addEventListener('click', (event) => {
    if (event.target === overlay) closeDialog();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !overlay.hidden) closeDialog();
  });

  confirmButton.addEventListener('click', async () => {
    if (requestInFlight || !consent.checked || !pendingPrompt.trim()) return;
    requestInFlight = true;
    let succeeded = false;
    confirmButton.disabled = true;
    $('#imageDialogError').textContent = 'Generating one image… Do not retry if the request times out; it may have been billed.';
    const body = {
      prompt: pendingPrompt,
      size: $('#imageSize').value,
      quality: $('#imageQuality').value,
      output_format: $('#imageFormat').value,
      confirm_cloud_cost: true,
    };
    try {
      const response = await fetch('/api/images/generations', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-Genesis-Image-Token': csrfToken,
          'X-Marina-CSRF': decodeURIComponent((document.cookie.match(/(?:^|; )__Host-marina_csrf=([^;]+)/) || [,''])[1]) },
        body: JSON.stringify(body),
      });
      const data = await response.json();
      if (!response.ok) {
        const detail = data.detail || {};
        $('#imageDialogError').textContent = detail.message || 'Image generation failed. No automatic retry was made.';
        return;
      }
      if (!data.preview_url?.startsWith('/api/images/') || !data.download_url?.startsWith('/api/images/')) {
        $('#imageDialogError').textContent = 'The server returned an invalid image link.';
        return;
      }
      lastPrompt = pendingPrompt;
      showImageResult(data);
      succeeded = true;
      overlay.hidden = true;
      pendingPrompt = '';
      consent.checked = false;
    } catch {
      $('#imageDialogError').textContent = 'Could not complete the image request. The provider may have received it; check usage before trying again.';
    } finally {
      requestInFlight = false;
      if (!succeeded) consent.checked = false;
      updateConfirmation();
      if (!overlay.hidden) confirmButton.disabled = true;
    }
  });

  loadStatus();
})();
