/* Sign in / sign up page logic.

   Accounts live in this browser's localStorage under "ems_users". Passwords are never stored:
   each account keeps a random salt and a PBKDF2-SHA256 hash. Everything runs in the browser, so
   this is a sign-in screen for this browser, not server-side security. */
(function () {
  'use strict';

  var USERS_KEY = 'ems_users';
  var ITERATIONS = 600000;      // OWASP's current figure for PBKDF2-HMAC-SHA256
  var MIN_PASSWORD = 8;
  var MAX_PASSWORD = 128;
  var TITLES = { signin: 'Sign in', signup: 'Sign up' };
  var Session = window.EmsSession;

  // ---------- small helpers ----------

  function $(id) { return document.getElementById(id); }

  function fail(message) {
    var e = new Error(message);
    e.isAuthError = true;       // an error we can show to the person as-is
    return e;
  }

  function field(form, name) { return form.elements.namedItem(name); }
  function cleanName(s) { return s.replace(/\s+/g, ' ').trim(); }
  function cleanEmail(s) { return s.trim().toLowerCase(); }
  function validEmail(s) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s); }

  // ---------- storage ----------

  function loadUsers() {
    var raw;
    try { raw = localStorage.getItem(USERS_KEY); }
    catch (e) { throw fail('Browser storage is blocked. Allow site data for this page and try again.'); }
    if (!raw) { return []; }
    try {
      var list = JSON.parse(raw);
      if (Array.isArray(list)) { return list; }
    } catch (e) { /* fall through */ }
    throw fail('Saved accounts could not be read. Clear this site’s data in your browser to start fresh.');
  }

  function saveUsers(users) {
    try { localStorage.setItem(USERS_KEY, JSON.stringify(users)); }
    catch (e) { throw fail('Browser storage is blocked or full. Allow site data for this page and try again.'); }
  }

  // ---------- password hashing (Web Crypto) ----------

  function requireCrypto() {
    if (!window.crypto || !crypto.subtle) {
      throw fail('This address cannot hash passwords safely. Open the page from localhost or an https address.');
    }
  }

  function toBase64(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) { s += String.fromCharCode(bytes[i]); }
    return btoa(s);
  }

  function fromBase64(text) {
    var s = atob(text);
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) { out[i] = s.charCodeAt(i); }
    return out;
  }

  async function derive(password, salt, iterations) {
    var key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iterations }, key, 256);
    return new Uint8Array(bits);
  }

  function sameBytes(a, b) {
    if (a.length !== b.length) { return false; }
    var diff = 0;
    for (var i = 0; i < a.length; i++) { diff |= a[i] ^ b[i]; }
    return diff === 0;
  }

  // ---------- form feedback ----------

  function setError(input, message) {
    var out = $(input.id + '-err');
    var hint = $(input.id + '-hint');        // the grey guidance line, if this field has one
    out.textContent = message || '';
    out.hidden = !message;
    if (hint) { hint.hidden = !!message; }   // do not show guidance and an error saying the same thing
    if (message) { input.setAttribute('aria-invalid', 'true'); }
    else { input.removeAttribute('aria-invalid'); }
  }

  function setFormError(form, message) {
    var box = form.querySelector('.form-error');
    box.textContent = message || '';
    box.hidden = !message;
  }

  function clearErrors(form) {
    [].forEach.call(form.querySelectorAll('input'), function (input) { setError(input, ''); });
    setFormError(form, '');
  }

  // errors is { fieldName: message }. Focuses the first invalid field in page order.
  function showErrors(form, errors) {
    var first = null;
    [].forEach.call(form.querySelectorAll('input'), function (input) {
      var message = errors[input.name] || '';
      setError(input, message);
      if (message && !first) { first = input; }
    });
    if (first) { first.focus(); }
  }

  function setBusy(form, busy) {
    var button = form.querySelector('.submit');
    if (busy) { button.dataset.label = button.textContent; }
    button.disabled = busy;
    button.textContent = busy ? form.dataset.busy : button.dataset.label;
    form.setAttribute('aria-busy', String(busy));
  }

  // ---------- the two actions ----------
  // Each resolves true once it has started navigating to the app, false when it stayed on the page.

  async function signUp(form) {
    var name = cleanName(field(form, 'name').value);
    var email = cleanEmail(field(form, 'email').value);
    var password = field(form, 'password').value;
    var confirm = field(form, 'confirm').value;

    var errors = {};
    if (name.length < 2) { errors.name = 'Enter your full name.'; }
    if (!validEmail(email)) { errors.email = 'Enter a valid email address.'; }
    if (password.length < MIN_PASSWORD) { errors.password = 'Use at least ' + MIN_PASSWORD + ' characters.'; }
    else if (password.length > MAX_PASSWORD) { errors.password = 'Use ' + MAX_PASSWORD + ' characters or fewer.'; }
    else if (password !== confirm) { errors.confirm = 'Passwords don’t match.'; }
    if (Object.keys(errors).length) { showErrors(form, errors); return false; }

    requireCrypto();
    var exists = function (list) { return list.some(function (u) { return u.email === email; }); };
    if (exists(loadUsers())) {
      showErrors(form, { email: 'An account with this email already exists. Sign in instead.' });
      return false;
    }

    var salt = crypto.getRandomValues(new Uint8Array(16));
    var hash = await derive(password, salt, ITERATIONS);

    var users = loadUsers();          // read again: another tab may have signed up while we were hashing
    if (exists(users)) {
      showErrors(form, { email: 'An account with this email already exists. Sign in instead.' });
      return false;
    }
    users.push({
      name: name,
      email: email,
      salt: toBase64(salt),
      hash: toBase64(hash),
      iterations: ITERATIONS,
      createdAt: new Date().toISOString()
    });
    saveUsers(users);

    Session.start({ name: name, email: email });
    location.replace(Session.HOME_PAGE);
    return true;
  }

  async function signIn(form) {
    var email = cleanEmail(field(form, 'email').value);
    var password = field(form, 'password').value;

    var errors = {};
    if (!email) { errors.email = 'Enter your email.'; }
    if (!password) { errors.password = 'Enter your password.'; }
    if (Object.keys(errors).length) { showErrors(form, errors); return false; }

    requireCrypto();
    var user = loadUsers().filter(function (u) { return u.email === email; })[0];
    var ok = false;
    if (user) {
      var hash = await derive(password, fromBase64(user.salt), user.iterations);
      ok = sameBytes(hash, fromBase64(user.hash));
    }
    if (!ok) {
      // Same message for "no such account" and "wrong password".
      setFormError(form, 'Email or password is incorrect.');
      field(form, 'password').focus();
      return false;
    }

    Session.start({ name: user.name, email: user.email });
    location.replace(Session.HOME_PAGE);
    return true;
  }

  function handle(form, action) {
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      if (form.getAttribute('aria-busy') === 'true') { return; }
      clearErrors(form);
      setBusy(form, true);
      action(form).then(function (navigating) {
        if (!navigating) { setBusy(form, false); }
      }, function (err) {
        if (err && err.isAuthError) { setFormError(form, err.message); }
        else {
          setFormError(form, 'Something went wrong. Reload the page and try again.');
          if (window.console) { console.error(err); }
        }
        setBusy(form, false);
      });
    });
  }

  // ---------- tabs ----------

  var tabs = [].slice.call(document.querySelectorAll('[role="tab"]'));
  var forms = [$('signin-form'), $('signup-form')];

  function show(mode, focusTab) {
    tabs.forEach(function (tab) {
      var on = tab.dataset.mode === mode;
      tab.setAttribute('aria-selected', String(on));
      tab.tabIndex = on ? 0 : -1;
      $(tab.getAttribute('aria-controls')).hidden = !on;
      if (on && focusTab) { tab.focus(); }
    });
    forms.forEach(clearErrors);
    document.title = TITLES[mode] + ' | HR Employee Manager Pro';
    try { history.replaceState(null, '', '#' + mode); } catch (e) { /* some browsers block this on file:// */ }
  }

  function focusFirstField(mode) {
    var input = $(mode === 'signup' ? 'su-name' : 'si-email');
    if (input) { input.focus(); }
  }

  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () { show(tab.dataset.mode, false); });
  });

  document.querySelector('[role="tablist"]').addEventListener('keydown', function (event) {
    var i = tabs.indexOf(document.activeElement);
    if (i < 0) { return; }
    var target = { ArrowRight: (i + 1) % tabs.length, ArrowLeft: (i + tabs.length - 1) % tabs.length,
                   Home: 0, End: tabs.length - 1 }[event.key];
    if (target === undefined) { return; }
    event.preventDefault();
    show(tabs[target].dataset.mode, true);
  });

  [].forEach.call(document.querySelectorAll('[data-switch]'), function (link) {
    link.addEventListener('click', function () {
      show(link.dataset.switch, false);
      focusFirstField(link.dataset.switch);
    });
  });

  // ---------- wiring ----------

  [].forEach.call(document.querySelectorAll('.reveal'), function (button) {
    button.addEventListener('click', function () {
      var input = $(button.getAttribute('aria-controls'));
      var revealing = input.type === 'password';
      input.type = revealing ? 'text' : 'password';
      button.textContent = revealing ? 'Hide' : 'Show';
      button.setAttribute('aria-label', (revealing ? 'Hide ' : 'Show ') + button.dataset.what);
    });
  });

  [].forEach.call(document.querySelectorAll('input'), function (input) {
    input.addEventListener('input', function () {
      setError(input, '');
      setFormError(input.form, '');
    });
  });

  handle($('signin-form'), signIn);
  handle($('signup-form'), signUp);

  function modeFromHash() { return location.hash === '#signup' ? 'signup' : 'signin'; }

  // Typing #signup or #signin into the address bar of an open page switches tabs too.
  // (replaceState in show() does not fire this, so there is no loop.)
  window.addEventListener('hashchange', function () {
    show(modeFromHash(), false);
    focusFirstField(modeFromHash());
  });

  show(modeFromHash(), false);
  focusFirstField(modeFromHash());
})();
