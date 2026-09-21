/* aec.js — AEC Command Center (EPIC8).
   Client-side polish only: swaps loading notes in for server-rendered
   content. No network calls, no mutation, no execution. */

(function () {
  "use strict";

  function onReady(fn) {
    if (document.readyState !== "loading") {
      fn();
    } else {
      document.addEventListener("DOMContentLoaded", fn);
    }
  }

  onReady(function () {
    var loaders = document.querySelectorAll("[data-aec-loading]");
    for (var i = 0; i < loaders.length; i += 1) {
      loaders[i].hidden = true;
    }
    var errors = document.querySelectorAll("[data-aec-error]");
    for (var j = 0; j < errors.length; j += 1) {
      errors[j].hidden = true;
    }
  });
})();