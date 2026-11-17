(() => {
  const status = document.getElementById('accountStatus');
  const signIn = document.getElementById('googleSignIn');
  const signOut = document.getElementById('googleSignOut');
  const notice = document.getElementById('accountNotice');
  const privacyDetail = document.querySelector('.local-card small');
  const emailForm = document.getElementById('emailAuthForm');
  const emailInput = document.getElementById('emailAuthAddress');
  const emailMessage = document.getElementById('emailAuthMessage');
  if (!status || !signIn || !signOut || !notice) return;

  function cookie(name) {
    const prefix = `${name}=`;
    const item = document.cookie.split('; ').find((part) => part.startsWith(prefix));
    return item ? decodeURIComponent(item.slice(prefix.length)) : '';
  }

  async function refresh() {
    try {
      const response = await fetch('/auth/status', { cache: 'no-store', credentials: 'same-origin' });
      const data = await response.json();
      if (!response.ok) throw new Error('status');
      signIn.hidden = !data.configured || data.authenticated;
      signOut.hidden = !data.authenticated;
      status.textContent = data.authenticated ? `Signed in as ${data.email || 'Google account'}` :
        (data.configured ? 'Account sign-in is optional' : 'Google sign-in is not configured');
      notice.textContent = data.notice || 'Sign in to sync new conversations; pre-account data remains separate.';
      if (privacyDetail) privacyDetail.textContent = data.authenticated ?
        'Your account conversations sync securely across devices.' :
        'Anonymous chats are tied to this browser, not an account. The browser identity expires after 30 days; expiry does not delete stored chats.';
    } catch (_) {
      status.textContent = 'Account status unavailable';
      signOut.hidden = true;
    }
  }

  async function refreshEmailAuth() {
    if (!emailForm) return;
    try {
      const response = await fetch('/auth/email/status', { cache: 'no-store', credentials: 'same-origin' });
      const data = await response.json();
      emailForm.hidden = !response.ok || !data.configured;
    } catch (_) {
      emailForm.hidden = true;
    }
  }

  async function requestEmailAction(path) {
    if (!emailInput || !emailMessage || !emailInput.reportValidity()) return;
    const buttons = emailForm.querySelectorAll('button');
    buttons.forEach((button) => { button.disabled = true; });
    emailMessage.textContent = 'Sending request…';
    try {
      const response = await fetch(path, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: emailInput.value })
      });
      const data = await response.json();
      emailMessage.textContent = data.message || 'If the address can use this method, check your email for next steps.';
    } catch (_) {
      emailMessage.textContent = 'The request could not be completed. Please try again later.';
    } finally {
      buttons.forEach((button) => { button.disabled = false; });
    }
  }

  document.getElementById('emailSignInRequest')?.addEventListener('click', () => requestEmailAction('/auth/email/sign-in'));
  document.getElementById('emailRecoveryRequest')?.addEventListener('click', () => requestEmailAction('/auth/email/recovery'));

  signOut.addEventListener('click', async () => {
    signOut.disabled = true;
    try {
      const csrf = cookie('__Host-marina_csrf');
      const response = await fetch('/auth/logout', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'X-Marina-CSRF': csrf }
      });
      if (!response.ok) throw new Error('logout');
      await refresh();
    } catch (_) {
      status.textContent = 'Sign out failed. Please try again.';
    } finally {
      signOut.disabled = false;
    }
  });
  refresh();
  refreshEmailAuth();
})();
