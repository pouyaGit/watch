// app.js — small interactive bits the templates rely on.
//
// Phase 1 only needs:
//   1) a "refresh" custom event on the task card so a successful Run Now
//      button retriggers the htmx pollers attached to that card (htmx
//      doesn't auto-refresh siblings when hx-swap="none" is used).
//
// Everything else (the live status badge swap, the system stats poll) is
// done entirely via htmx attributes in the templates -- no JS required.

document.body.addEventListener('htmx:afterRequest', function (evt) {
  // If a Run Now POST just succeeded, force the status badge poll to re-run
  // immediately so the UI doesn't have to wait up to 3s for the next tick.
  var card = evt.target.closest('.program-card');
  if (card && card.id && card.id.startsWith('task-card-')) {
    htmx.trigger(card, 'refresh');
  }
});

// Keep "Run now" from being clicked twice in rapid succession.
document.body.addEventListener('htmx:beforeRequest', function (evt) {
  if (evt.target.matches('button[hx-post]')) {
    evt.target.disabled = true;
    var original = evt.target.textContent;
    evt.target.textContent = '… launching';
    setTimeout(function () {
      evt.target.disabled = false;
      evt.target.textContent = original;
    }, 1500);
  }
});