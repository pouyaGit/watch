(function () {
  "use strict";

  function postJSON(url, payload) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(payload || {}),
      credentials: "same-origin",
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        if (!r.ok) throw new Error(body.detail || ("HTTP " + r.status));
        return body;
      });
    });
  }

  document.addEventListener("click", function (ev) {
    var t = ev.target;

    var menuBtn = t.closest("[data-menu-toggle]");
    if (menuBtn) {
      var menu = menuBtn.closest(".menu");
      document.querySelectorAll(".menu.open").forEach(function (m) { if (m !== menu) m.classList.remove("open"); });
      menu.classList.toggle("open");
      return;
    }
    if (!t.closest(".menu")) {
      document.querySelectorAll(".menu.open").forEach(function (m) { m.classList.remove("open"); });
    }

    var runBtn = t.closest("[data-run]");
    if (runBtn) {
      ev.preventDefault();
      var taskId = runBtn.getAttribute("data-run");
      var target = runBtn.getAttribute("data-target") || null;
      runBtn.disabled = true;
      postJSON("/api/tasks/" + encodeURIComponent(taskId) + "/run", { target: target })
        .then(function () { location.reload(); })
        .catch(function (err) { alert("Run failed: " + err.message); runBtn.disabled = false; });
      return;
    }

    var stopBtn = t.closest("[data-stop]");
    if (stopBtn) {
      ev.preventDefault();
      var runId = stopBtn.getAttribute("data-run-id");
      var stopTask = stopBtn.getAttribute("data-stop");
      stopBtn.disabled = true;
      postJSON("/api/tasks/" + encodeURIComponent(stopTask) + "/stop?run_id=" + encodeURIComponent(runId), {})
        .then(function () { location.reload(); })
        .catch(function (err) { alert("Stop failed: " + err.message); stopBtn.disabled = false; });
      return;
    }

    var postBtn = t.closest("[data-post]");
    if (postBtn) {
      ev.preventDefault();
      var confirmMsg = postBtn.getAttribute("data-confirm");
      if (confirmMsg && !window.confirm(confirmMsg)) return;
      postBtn.disabled = true;
      postJSON(postBtn.getAttribute("data-post"), {})
        .then(function () {
          if (postBtn.hasAttribute("data-reload")) { location.reload(); return; }
          postBtn.disabled = false;
          refreshLive();
        })
        .catch(function (err) { alert("Action failed: " + err.message); postBtn.disabled = false; });
      return;
    }

    var logBtn = t.closest("[data-log-run]");
    if (logBtn) {
      ev.preventDefault();
      openLog(logBtn.getAttribute("data-log-run"), logBtn.getAttribute("data-log-title"));
      return;
    }
    if (t.closest("[data-log-close]")) {
      closeLog();
      return;
    }

    var copy = t.closest("[data-copy]");
    if (copy && navigator.clipboard) {
      navigator.clipboard.writeText(copy.getAttribute("data-copy")).then(function () {
        copy.textContent = "copied";
        setTimeout(function () { copy.textContent = "copy"; }, 1200);
      });
      return;
    }
  });

  document.querySelectorAll("form[data-confirm-name]").forEach(function (form) {
    var expected = form.getAttribute("data-confirm-name");
    var input = form.querySelector("input[name=confirm]");
    var btn = form.querySelector("button[type=submit]");
    if (!input || !btn) return;
    btn.disabled = true;
    input.addEventListener("input", function () { btn.disabled = input.value !== expected; });
  });

  document.querySelectorAll("table.data").forEach(function (table) {
    var body = table.tBodies[0];
    if (!body) return;
    table.querySelectorAll("th[data-sort]").forEach(function (th, idx) {
      th.addEventListener("click", function () {
        var asc = th.getAttribute("data-dir") !== "asc";
        table.querySelectorAll("th[data-sort]").forEach(function (o) { o.removeAttribute("data-dir"); });
        th.setAttribute("data-dir", asc ? "asc" : "desc");
        var col = Array.prototype.indexOf.call(th.parentNode.children, th);
        var rows = Array.prototype.slice.call(body.rows);
        rows.sort(function (a, b) {
          var x = a.cells[col].textContent.trim(), y = b.cells[col].textContent.trim();
          var nx = parseFloat(x), ny = parseFloat(y);
          var cmp = (!isNaN(nx) && !isNaN(ny)) ? nx - ny : x.localeCompare(y);
          return asc ? cmp : -cmp;
        });
        rows.forEach(function (r) { body.appendChild(r); });
      });
    });
    table.querySelectorAll("input.colfilter").forEach(function (input) {
      var col = parseInt(input.getAttribute("data-col"), 10);
      input.addEventListener("input", function () {
        var needle = input.value.toLowerCase();
        Array.prototype.forEach.call(body.rows, function (row) {
          var text = (row.cells[col] ? row.cells[col].textContent : "").toLowerCase();
          row.style.display = text.indexOf(needle) === -1 ? "none" : "";
        });
      });
    });
  });

  var HEAVY_UNIT = "watch-heavy.service";
  var HEAVY_COMMANDS = [
    ["skip", "skip lane", "Skip the current lane? The running tool will be terminated."],
    ["pause", "pause", null],
    ["resume", "resume", null],
    ["stop-after-lane", "stop after lane", null],
  ];
  var liveBody = document.getElementById("live-body");
  var liveUpdated = document.getElementById("live-updated");

  function el(tag, value, cls) {
    var node = document.createElement(tag);
    node.textContent = value == null ? "" : String(value);
    if (cls) node.className = cls;
    return node;
  }

  function actionButton(label, url, confirmMsg) {
    var b = el("button", label, "btn");
    b.type = "button";
    b.setAttribute("data-post", url);
    if (confirmMsg) b.setAttribute("data-confirm", confirmMsg);
    return b;
  }

  function fmtElapsed(sec) {
    if (sec == null) return "—";
    var h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    if (h) return h + "h " + m + "m";
    if (m) return m + "m " + s + "s";
    return s + "s";
  }

  function scopeLabel(row) {
    if (row.source === "systemd") return "—";
    if (row.scope && row.scope.length) return row.scope.join(", ");
    return row.target || "all";
  }

  function actionsCell(row) {
    var td = document.createElement("td");
    td.style.whiteSpace = "nowrap";
    var live = ["running", "starting", "paused"];
    if (row.source === "systemd") {
      if (row.unit === HEAVY_UNIT && live.indexOf(row.status) !== -1) {
        HEAVY_COMMANDS.forEach(function (c) {
          td.appendChild(actionButton(c[1], "/api/heavy/control/" + c[0], c[2]));
          td.appendChild(document.createTextNode(" "));
        });
      }
      if (live.indexOf(row.status) !== -1) {
        td.appendChild(actionButton("stop", "/api/system/" + row.unit + "/stop",
          "Stop " + row.unit + "?"));
        td.appendChild(document.createTextNode(" "));
      }
      td.appendChild(actionButton("restart", "/api/system/" + row.unit + "/restart",
        "Restart " + row.unit + "?"));
      return td;
    }

    var rid = encodeURIComponent(row.run_id);
    var logB = el("button", "log", "btn");
    logB.type = "button";
    logB.setAttribute("data-log-run", row.run_id);
    logB.setAttribute("data-log-title", row.name || "log");
    td.appendChild(logB);
    td.appendChild(document.createTextNode(" "));
    if (row.status === "paused") {
      td.appendChild(actionButton("resume", "/api/tasks/runs/" + rid + "/resume"));
    } else if (row.status === "running") {
      td.appendChild(actionButton("pause", "/api/tasks/runs/" + rid + "/pause"));
    }
    td.appendChild(document.createTextNode(" "));
    td.appendChild(actionButton("stop", "/api/tasks/runs/" + rid + "/stop", "Stop this run?"));
    if (row.group_id) {
      var gid = encodeURIComponent(row.group_id);
      td.appendChild(document.createTextNode(" "));
      td.appendChild(actionButton("next", "/api/groups/" + gid + "/next"));
      td.appendChild(document.createTextNode(" "));
      td.appendChild(actionButton("stop group", "/api/groups/" + gid + "/stop", "Stop every run in this group?"));
    }
    return td;
  }

  function renderLive(rows) {
    liveBody.textContent = "";
    if (!rows.length) {
      var empty = document.createElement("tr");
      empty.appendChild(el("td", "Nothing running.", "muted"));
      empty.firstChild.colSpan = 6;
      liveBody.appendChild(empty);
      return;
    }
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      var nameTd = document.createElement("td");
      nameTd.appendChild(el("strong", row.name));
      if (row.unit) nameTd.appendChild(el("div", row.unit, "muted mono"));
      tr.appendChild(nameTd);
      tr.appendChild(el("td", scopeLabel(row)));
      var stTd = document.createElement("td");
      stTd.appendChild(el("span", row.status, "badge-status st-" + row.status));
      tr.appendChild(stTd);
      tr.appendChild(el("td", fmtElapsed(row.elapsed_seconds)));
      tr.appendChild(el("td", row.activity || "", "mono"));
      tr.appendChild(actionsCell(row));
      liveBody.appendChild(tr);
    });
  }

  function refreshLive() {
    if (!liveBody) return Promise.resolve();
    return fetch("/api/tasks/live", { credentials: "same-origin", headers: { "Accept": "application/json" } })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (rows) {
        renderLive(rows);
        liveUpdated.textContent = "updated " + new Date().toLocaleTimeString();
      })
      .catch(function (err) { liveUpdated.textContent = "refresh failed: " + err.message; });
  }

  if (liveBody) {
    refreshLive();
    setInterval(refreshLive, 5000);
  }

  var launchForm = document.getElementById("launch-form");
  if (launchForm) {
    var launchMsg = document.getElementById("launch-msg");

    function checkedValue(name) {
      var node = launchForm.querySelector("input[name=" + name + "]:checked");
      return node ? node.value : null;
    }

    function syncScope() {
      var whole = Array.prototype.some.call(
        launchForm.querySelectorAll("input[name=tools]:checked"),
        function (cb) { return cb.getAttribute("data-whole-db") === "1"; });
      launchForm.querySelectorAll("input[name=scope_kind]").forEach(function (r) {
        r.disabled = whole && r.value !== "all";
      });
      if (whole) launchForm.querySelector("input[name=scope_kind][value=all]").checked = true;
      var kind = checkedValue("scope_kind");
      launchForm.querySelector(".scope-programs").hidden = kind !== "programs";
      launchForm.querySelector(".scope-domains").hidden = kind !== "domains";
    }

    function buildPayload() {
      var kind = checkedValue("scope_kind");
      var scope = [];
      if (kind === "programs") {
        scope = Array.prototype.map.call(
          launchForm.querySelectorAll("select[name=programs] option:checked"),
          function (o) { return o.value; });
      } else if (kind === "domains") {
        scope = launchForm.querySelector("textarea[name=domains]").value.split(/[\s,]+/).filter(Boolean);
      }
      var maxMinutes = null;
      if (checkedValue("duration") === "minutes") {
        maxMinutes = parseInt(launchForm.querySelector("input[name=minutes]").value, 10);
      }
      return {
        tools: Array.prototype.map.call(launchForm.querySelectorAll("input[name=tools]:checked"),
          function (cb) { return cb.value; }),
        scope_kind: kind,
        scope: scope,
        max_minutes: maxMinutes,
      };
    }

    launchForm.addEventListener("change", syncScope);
    syncScope();

    launchForm.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var btn = launchForm.querySelector("button[type=submit]");
      btn.disabled = true;
      launchMsg.textContent = "starting…";
      postJSON("/api/runs", buildPayload())
        .then(function (res) {
          var text = res.created + " started";
          if (res.skipped) text += ", " + res.skipped + " skipped";
          launchMsg.textContent = text;
          return refreshLive();
        })
        .catch(function (err) { launchMsg.textContent = err.message; })
        .then(function () { btn.disabled = false; });
    });
  }

  var logDialog = document.getElementById("log-drawer");
  var logRunId = null;
  var logTimer = null;

  function pollLog() {
    var id = logRunId;
    if (!id) return;
    fetch("/api/tasks/runs/" + encodeURIComponent(id) + "/log?tail=300", { credentials: "same-origin" })
      .then(function (r) {
        return r.text().then(function (body) {
          if (!r.ok) throw new Error(body || ("HTTP " + r.status));
          return body;
        });
      })
      .then(function (body) {
        if (id !== logRunId) return;
        var pre = document.getElementById("log-text");
        var atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 20;
        pre.textContent = body;
        if (atBottom) pre.scrollTop = pre.scrollHeight;
        document.getElementById("log-state").textContent = "updated " + new Date().toLocaleTimeString();
      })
      .catch(function (err) { document.getElementById("log-state").textContent = err.message; });
  }

  function openLog(runId, title) {
    if (!logDialog) return;
    logRunId = runId;
    document.getElementById("log-title").textContent = title || "log";
    document.getElementById("log-text").textContent = "";
    if (logDialog.showModal) logDialog.showModal(); else logDialog.setAttribute("open", "");
    pollLog();
    clearInterval(logTimer);
    logTimer = setInterval(pollLog, 3000);
  }

  function closeLog() {
    logRunId = null;
    clearInterval(logTimer);
    if (logDialog && logDialog.open) logDialog.close();
  }

  if (logDialog) logDialog.addEventListener("close", closeLog);

  if (document.querySelector("[data-autorefresh]")) {
    setInterval(function () {
      if (document.querySelector(".menu.open")) return;
      location.reload();
    }, 5000);
  }
})();
