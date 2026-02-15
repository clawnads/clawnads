// analytics-beacon.js — Lightweight client-side analytics for Clawnads
// Tracks session duration, page enters, tab switches, drawer opens
(function() {
  'use strict';
  var SESSION_ID = Math.random().toString(36).slice(2, 10);
  var sessionStart = Date.now();
  var pageCount = 1;

  function beacon(type, data) {
    var payload = JSON.stringify({ type: type, data: Object.assign({ sessionId: SESSION_ID }, data || {}) });
    // Use sendBeacon with Blob for correct Content-Type
    if (navigator.sendBeacon) {
      var blob = new Blob([payload], { type: 'application/json' });
      navigator.sendBeacon('/analytics/event', blob);
    } else {
      fetch('/analytics/event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        keepalive: true
      }).catch(function() {});
    }
  }

  // Page enter
  beacon('page_enter', { page: location.pathname });

  // Session heartbeat — every 30 seconds
  setInterval(function() {
    var durationSec = Math.round((Date.now() - sessionStart) / 1000);
    beacon('session_heartbeat', { durationSec: durationSec, page: location.pathname, pageCount: pageCount });
  }, 30000);

  // Session end on page unload
  window.addEventListener('beforeunload', function() {
    var durationSec = Math.round((Date.now() - sessionStart) / 1000);
    beacon('session_end', { durationSec: durationSec, page: location.pathname, pageCount: pageCount });
  });

  // Expose for app.js to call
  window.__beacon = beacon;
  window.__beaconPageCount = function() { return ++pageCount; };
})();
