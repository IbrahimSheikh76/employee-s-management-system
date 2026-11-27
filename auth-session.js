/* Session helpers shared by auth.html and index.html.
   Loaded in <head> so a signed-out visitor is redirected before the page paints.
   data-guard="require": the page needs a session. data-guard="guest": skip ahead if signed in. */
(function () {
  'use strict';

  var KEY = 'ems_session';
  var HOURS = 8;
  var AUTH_PAGE = 'auth.html';
  var HOME_PAGE = 'index.html';
  var mode = document.currentScript && document.currentScript.dataset.guard;

  function current() {
    try {
      var s = JSON.parse(sessionStorage.getItem(KEY));
      if (s && typeof s.email === 'string' && s.expiresAt > Date.now()) { return s; }
    } catch (e) { /* storage blocked or corrupt: treat as signed out */ }
    return null;
  }

  function start(user) {
    sessionStorage.setItem(KEY, JSON.stringify({
      name: user.name,
      email: user.email,
      expiresAt: Date.now() + HOURS * 60 * 60 * 1000
    }));
  }

  function end() {
    try { sessionStorage.removeItem(KEY); } catch (e) { /* nothing to clear */ }
  }

  function enforce() {
    if (mode === 'require' && !current()) {
      document.documentElement.style.visibility = 'hidden';
      location.replace(AUTH_PAGE);
    } else if (mode === 'guest' && current()) {
      location.replace(HOME_PAGE);
    }
  }

  window.EmsSession = { current: current, start: start, end: end, HOME_PAGE: HOME_PAGE, AUTH_PAGE: AUTH_PAGE };

  enforce();
  // Back button after signing out can restore a cached copy of the page: check again.
  window.addEventListener('pageshow', function (e) { if (e.persisted) { enforce(); } });
  // Catch a session that expired while the tab sat in the background.
  document.addEventListener('visibilitychange', function () { if (!document.hidden) { enforce(); } });

  // Signed-in bar on index.html (does nothing on the sign-in page).
  document.addEventListener('DOMContentLoaded', function () {
    var who = document.getElementById('whoami');
    var out = document.getElementById('signout');
    var s = current();
    if (who && s) { who.textContent = s.name; }   // textContent, never innerHTML: the name is user input
    if (out) {
      out.addEventListener('click', function () {
        end();
        location.replace(AUTH_PAGE);
      });
    }
  });
})();
