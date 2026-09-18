/* research_dashboard.js — Stage R82 Research Dashboard UI.
 *
 * UI-only client for the R81 researcher API contract:
 *   GET  /api/research/cases
 *   GET  /api/research/cases/{case_id}
 *   POST /api/research/cases/{case_id}/evidence
 *
 * The backend remains authoritative for every validation and state
 * transition; this file renders bounded API data with textContent only
 * (never HTML injection) and never submits anything Watch did not
 * define in the R80 envelope.
 *
 * Authentication reuses the existing convention: the API key is read from
 * `window.location.search` at runtime. No key is ever embedded here.
 */
(function () {
  'use strict';

  var API_CASES = '/api/research/cases';
  var currentRequest = null;

  // ---------- runtime API key (existing dashboard convention) ----------
  function apiKey() {
    return new URLSearchParams(window.location.search).get('api_key') || '';
  }

  function withKey(path) {
    var key = apiKey();
    if (!key) return path;
    var separator = path.indexOf('?') === -1 ? '?' : '&';
    return path + separator + 'api_key=' + encodeURIComponent(key);
  }

  function homeUrl() {
    var key = apiKey();
    return key ? '/?api_key=' + encodeURIComponent(key) : '/';
  }

  // ---------- bounded fetch with explicit states ----------
  async function apiFetch(path, options) {
    var response;
    try {
      response = await fetch(withKey(path), options || {});
    } catch (error) {
      return { state: 'unavailable', status: 0, body: null };
    }
    var body = null;
    try {
      body = await response.json();
    } catch (error) {
      body = null;
    }
    if (response.status === 401) {
      return { state: 'unauthorized', status: 401, body: body };
    }
    if (response.status === 404) {
      return { state: 'not-found', status: 404, body: body };
    }
    if (!response.ok) {
      var code = '';
      if (body && typeof body.detail === 'string') {
        code = body.detail.split(':')[0];
      }
      return { state: 'rejected', status: response.status, code: code, body: body };
    }
    return { state: 'ok', status: response.status, body: body };
  }

  // ---------- tiny DOM helpers (no HTML injection for dynamic data) ----------
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null && text !== '') {
      node.textContent = String(text);
    }
    return node;
  }

  function clear(node) {
    if (node) node.replaceChildren();
  }

  function badge(text, className) {
    var node = el('span', 'badge ' + (className || 'badge-neutral'));
    var dot = el('span', 'dot');
    node.appendChild(dot);
    node.appendChild(document.createTextNode(String(text)));
    return node;
  }

  function chip(text, className) {
    return el('span', 'r82-chip ' + (className || ''), text);
  }

  function mono(text) {
    return el('code', 'r82-mono', text);
  }

  function panel(title, id) {
    var wrap = el('section', 'panel r82-panel');
    if (id) wrap.id = id;
    var head = el('div', 'panel-head');
    head.appendChild(el('h2', null, title));
    wrap.appendChild(head);
    var body = el('div', 'panel-body');
    wrap.appendChild(body);
    return { root: wrap, body: body };
  }

  function list(items, emptyText) {
    var wrap = el('div', 'r82-kv');
    if (!items || !items.length) {
      wrap.appendChild(el('p', 'r82-empty', emptyText || 'none'));
      return wrap;
    }
    items.forEach(function (item) {
      wrap.appendChild(el('p', 'r82-kv-line', item));
    });
    return wrap;
  }

  function kindsBlock(label, kinds, emptyText) {
    var wrap = el('div', 'r82-kinds');
    wrap.appendChild(el('p', 'r82-kv-label', label));
    if (!kinds || !kinds.length) {
      wrap.appendChild(el('p', 'r82-empty', emptyText || 'none'));
      return wrap;
    }
    var row = el('div', 'r82-chip-row');
    kinds.forEach(function (kind) {
      row.appendChild(chip(kind, 'r82-chip-kind'));
    });
    wrap.appendChild(row);
    return wrap;
  }

  // ---------- display-only label maps (no validation, no ranking) ----------
  var WORKFLOW_ACTION_LABELS = {
    REVIEW_EVIDENCE: 'Review evidence',
    PROVIDE_EVIDENCE: 'Provide evidence',
    REVIEW_CONFLICT: 'Review conflict',
    CONTINUE_RESEARCH: 'Continue research',
    HUMAN_REVIEW: 'Human review',
    STOP: 'Stop'
  };

  var REJECTION_HINTS = {
    MALFORMED_ENVELOPE: 'The submission envelope is malformed.',
    UNSUPPORTED_SUBMISSION_VERSION: 'Unsupported submission version.',
    CASE_REF_REQUIRED: 'case_ref is required.',
    UNKNOWN_CASE: 'Unknown case.',
    CASE_MISMATCH: 'The submission case_ref does not match the case.',
    CASE_STATE_UNAVAILABLE: 'Case state is unavailable.',
    UNKNOWN_REQUIREMENT_FOR_CASE: 'Requirement does not belong to this case.',
    HYPOTHESIS_NOT_IN_CASE: 'Hypothesis does not belong to this case.',
    SUBMITTER_NOT_ALLOWED: 'Submitter label is not allowed.',
    SENSITIVE_SUBMISSION_REJECTED: 'Sensitive evidence rejected by the boundary.',
    EXECUTION_CONTENT_REJECTED: 'Execution content rejected by the boundary.',
    SUBMISSION_TOO_LARGE: 'Submission exceeds the bounded size.',
    INVALID_EVIDENCE_SOURCE: 'Unsupported source (rejected by the R74 intake).',
    DUPLICATE_EVIDENCE: 'Duplicate evidence (rejected by the R74 intake).',
    INTERNAL_PROCESSING_FAILURE: 'Internal processing failure.'
  };

  // ---------- status vocabulary (aligned with the API) ----------
  var STATUS_CLASS = {
    WAITING_FOR_EVIDENCE: 'badge-neutral',
    ACTIVE: 'badge-running',
    READY_FOR_HUMAN_REVIEW: 'badge-warn',
    STOPPED: 'badge-err'
  };

  var READINESS_CLASS = {
    INSUFFICIENT: 'badge-err',
    PARTIALLY_SUFFICIENT: 'badge-warn',
    SUFFICIENT_FOR_REVIEW: 'badge-ok'
  };

  function statusBadge(status) {
    return badge(status || 'UNKNOWN', STATUS_CLASS[status] || 'badge-idle');
  }

  function readinessBadge(readiness) {
    if (!readiness) return badge('—', 'badge-idle');
    return badge(readiness, READINESS_CLASS[readiness] || 'badge-idle');
  }

  function boolText(value) {
    return value ? 'Yes' : 'No';
  }

  // ---------- state panels ----------
  function showState(container, kind, message, detail) {
    clear(container);
    var box = el('div', 'r82-state r82-state-' + kind);
    box.appendChild(el('p', 'r82-state-title', message));
    if (detail) box.appendChild(el('p', 'r82-state-detail', detail));
    if (kind === 'unauthorized') {
      box.appendChild(
        el(
          'p',
          'r82-state-detail',
          'Append ?api_key=YOUR_KEY to the URL (existing dashboard convention).'
        )
      );
    }
    container.appendChild(box);
    container.hidden = false;
  }

  function hideState(container) {
    if (container) container.hidden = true;
  }

  // =====================================================================
  // CASE LIST
  // =====================================================================

  var listState = { items: [], filters: { search: '', status: '', review: '', sort: 'case_id' } };

  function renderListRows() {
    var tbody = document.getElementById('case-list-body');
    if (!tbody) return;
    var query = listState.filters.search.toLowerCase();
    var filtered = listState.items.filter(function (item) {
      if (listState.filters.status && item.status !== listState.filters.status) {
        return false;
      }
      if (listState.filters.review && boolText(item.human_review_required) !== listState.filters.review) {
        return false;
      }
      if (!query) return true;
      return [item.case_id, item.program, item.category, item.gap_id]
        .join(' ')
        .toLowerCase()
        .indexOf(query) !== -1;
    });
    var sortKey = listState.filters.sort;
    filtered.sort(function (a, b) {
      var left = String(a[sortKey] === undefined ? '' : a[sortKey]);
      var right = String(b[sortKey] === undefined ? '' : b[sortKey]);
      return left.localeCompare(right) || String(a.case_id).localeCompare(String(b.case_id));
    });

    clear(tbody);
    var emptyRow = document.getElementById('case-list-empty');
    if (emptyRow) emptyRow.hidden = filtered.length !== 0;
    filtered.forEach(function (item) {
      var row = document.createElement('tr');
      row.className = 'r82-row';

      var idCell = document.createElement('td');
      var link = el('a', 'r82-case-link', item.case_id);
      link.href = 'case.html' + (apiKey() ? '?api_key=' + encodeURIComponent(apiKey()) + '&' : '?') + 'case_id=' + encodeURIComponent(item.case_id);
      idCell.appendChild(link);
      row.appendChild(idCell);

      row.appendChild(el('td', null, item.program || '—'));
      row.appendChild(el('td', null, item.category || '—'));

      var statusCell = document.createElement('td');
      statusCell.appendChild(statusBadge(item.status));
      row.appendChild(statusCell);

      var readinessCell = document.createElement('td');
      readinessCell.appendChild(readinessBadge(item.readiness));
      row.appendChild(readinessCell);

      row.appendChild(el('td', null, item.decision || '—'));
      row.appendChild(el('td', null, String(item.evidence ? item.evidence.available_count : 0)));

      var missingCell = document.createElement('td');
      var missing = (item.missing_evidence && item.missing_evidence.decision_critical) || [];
      if (missing.length) {
        missing.forEach(function (kind) {
          missingCell.appendChild(chip(kind, 'r82-chip-missing'));
        });
      } else {
        missingCell.appendChild(el('span', 'r82-empty', 'none'));
      }
      row.appendChild(missingCell);

      var reviewCell = document.createElement('td');
      reviewCell.appendChild(
        item.human_review_required
          ? badge('REVIEW', 'badge-warn')
          : badge('no', 'badge-idle')
      );
      row.appendChild(reviewCell);

      row.appendChild(el('td', null, item.next_iteration || '—'));
      tbody.appendChild(row);
    });
  }

  function bindListControls() {
    var search = document.getElementById('case-search');
    var status = document.getElementById('case-status-filter');
    var review = document.getElementById('case-review-filter');
    var sort = document.getElementById('case-sort');
    if (search) {
      search.addEventListener('input', function () {
        listState.filters.search = search.value || '';
        renderListRows();
      });
    }
    if (status) {
      status.addEventListener('change', function () {
        listState.filters.status = status.value || '';
        renderListRows();
      });
    }
    if (review) {
      review.addEventListener('change', function () {
        listState.filters.review = review.value || '';
        renderListRows();
      });
    }
    if (sort) {
      sort.addEventListener('change', function () {
        listState.filters.sort = sort.value || 'case_id';
        renderListRows();
      });
    }
  }

  async function initCaseList() {
    var container = document.getElementById('case-list-state');
    showState(container, 'loading', 'Loading research cases…');
    var result = await apiFetch(API_CASES);
    if (result.state !== 'ok') {
      showState(
        container,
        result.state === 'unauthorized' ? 'unauthorized' : 'error',
        result.state === 'unauthorized'
          ? 'API key required'
          : result.state === 'unavailable'
            ? 'API unavailable'
            : 'Could not load cases',
        result.code || ''
      );
      return;
    }
    hideState(container);
    listState.items = (result.body && result.body.items) || [];
    var count = document.getElementById('case-count');
    if (count) count.textContent = String(listState.items.length);
    bindListControls();
    renderListRows();
  }

  // =====================================================================
  // CASE DETAIL / WORKBENCH
  // =====================================================================

  function caseIdFromUrl() {
    return new URLSearchParams(window.location.search).get('case_id') || '';
  }

  function section(current, title, id) {
    current.container.appendChild(el('p', 'section-label', title));
    var built = panel('', id);
    built.root.classList.add('r82-section');
    current.container.appendChild(built.root);
    return built.body;
  }

  function renderCurrentState(body, workbench, summary) {
    var state = workbench.current_state || {};
    var grid = el('div', 'r82-state-grid');
    function item(label, value, badgeNode) {
      var cell = el('div', 'r82-state-item');
      cell.appendChild(el('p', 'r82-kv-label', label));
      if (badgeNode) {
        cell.appendChild(badgeNode);
      } else {
        cell.appendChild(el('p', 'r82-kv-value', value || '—'));
      }
      grid.appendChild(cell);
    }
    item('Case status', null, statusBadge(state.status));
    item('Readiness', null, readinessBadge(state.readiness));
    item('Decision', state.decision);
    item('Feedback', state.feedback);
    item('Hypothesis state', state.hypothesis_state);
    item('Next iteration', state.next_iteration);
    item('Human review', boolText(state.human_review_required));
    item('Iterations', String(state.iteration_count || 0) + (state.history_truncated ? ' (truncated)' : ''));
    body.appendChild(grid);
    if (summary && summary.gap_id) {
      body.appendChild(
        el('p', 'r82-kv-line', 'Gap: ' + summary.gap_id + (summary.category ? ' · ' + summary.category : ''))
      );
    }
  }

  function renderWhatWeKnow(body, workbench) {
    var known = workbench.what_we_know || {};
    body.appendChild(
      kindsBlock('Available requirement kinds', known.available_requirement_kinds, 'no available evidence')
    );
    var counts = el('div', 'r82-kv');
    counts.appendChild(el('p', 'r82-kv-line', 'Available: ' + String(known.available_count || 0)));
    counts.appendChild(el('p', 'r82-kv-line', 'Accepted external evidence: ' + String(known.accepted_evidence_count || 0)));
    if (known.provenance_state) {
      counts.appendChild(el('p', 'r82-kv-line', 'Provenance state: ' + known.provenance_state));
    }
    if (known.evidence_states && known.evidence_states.length) {
      counts.appendChild(el('p', 'r82-kv-line', 'Evidence states: ' + known.evidence_states.join(', ')));
    }
    body.appendChild(counts);
    if (known.supporting_evidence_refs && known.supporting_evidence_refs.length) {
      var refs = el('div', 'r82-kv');
      refs.appendChild(el('p', 'r82-kv-label', 'Supporting evidence refs'));
      known.supporting_evidence_refs.forEach(function (ref) {
        refs.appendChild(el('p', 'r82-kv-line', ref));
      });
      body.appendChild(refs);
    }
  }

  function renderWhatIsMissing(body, workbench) {
    var missing = workbench.what_is_missing || {};
    var next = workbench.what_to_do_next || {};
    body.appendChild(
      kindsBlock('Missing requirement kinds', missing.missing_requirement_kinds, 'nothing missing')
    );

    var box = el('div', 'r82-missing-box');
    box.appendChild(el('p', 'r82-kv-label', 'Decision-critical missing'));
    var critical = missing.decision_critical_missing || [];
    if (!critical.length) {
      box.appendChild(el('p', 'r82-empty', 'none — decision evidence complete'));
    } else {
      var row = el('div', 'r82-chip-row');
      critical.forEach(function (kind) {
        row.appendChild(chip(kind, 'r82-chip-missing'));
      });
      box.appendChild(row);
    }
    body.appendChild(box);

    if (missing.requirement_details && missing.requirement_details.length) {
      missing.requirement_details.forEach(function (entry) {
        var detail = el('div', 'r82-requirement');
        detail.appendChild(el('p', 'r82-req-kind', entry.requirement_kind));
        detail.appendChild(el('p', 'r82-kv-line', 'Why required: ' + (entry.description || '—')));
        if (next.acquisition_method) {
          detail.appendChild(el('p', 'r82-kv-line', 'Acquisition method: ' + next.acquisition_method));
        }
        if (next.expected_result) {
          detail.appendChild(el('p', 'r82-kv-line', 'Expected result: ' + next.expected_result));
        }
        if (next.stopping_condition) {
          detail.appendChild(el('p', 'r82-kv-line', 'Stopping condition: ' + next.stopping_condition));
        }
        body.appendChild(detail);
      });
    }
    if (missing.acquisition_plan_ref) {
      body.appendChild(el('p', 'r82-kv-line', 'Acquisition plan: ' + missing.acquisition_plan_ref));
    }
  }

  function renderNext(body, workbench) {
    var next = workbench.what_to_do_next || {};
    var steps = workbench.next_steps || [];
    body.appendChild(el('p', 'r82-kv-label', 'Objective'));
    body.appendChild(el('p', 'r82-kv-value', next.objective || '—'));
    body.appendChild(el('p', 'r82-kv-line', 'Recommended: ' + (next.recommended_action || '—')));
    body.appendChild(el('p', 'r82-kv-line', 'Method: ' + (next.acquisition_method || '—')));
    if (next.sources && next.sources.length) {
      body.appendChild(el('p', 'r82-kv-line', 'Sources: ' + next.sources.join(', ')));
    }
    if (next.steps && next.steps.length) {
      var stepList = el('ol', 'r82-steps');
      next.steps.forEach(function (step) {
        stepList.appendChild(
          el('li', null, '[' + (step.source || '') + '] ' + (step.expected || ''))
        );
      });
      body.appendChild(stepList);
    }
    body.appendChild(el('p', 'r82-kv-line', 'Expected result: ' + (next.expected_result || '—')));
    body.appendChild(el('p', 'r82-kv-line', 'Stopping condition: ' + (next.stopping_condition || '—')));

    var actions = el('div', 'r82-kv');
    actions.appendChild(el('p', 'r82-kv-label', 'Next steps (max 3)'));
    if (!steps.length) {
      actions.appendChild(el('p', 'r82-empty', 'none'));
    } else {
      steps.slice(0, 3).forEach(function (step) {
        var line = el('div', 'r82-action');
        var actionCode = step.action || '';
        var actionLabel = WORKFLOW_ACTION_LABELS[actionCode] || '';
        line.appendChild(
          chip(actionLabel ? actionLabel + ' \u00b7 ' + actionCode : actionCode, 'r82-chip-action')
        );
        if (step.reason) line.appendChild(el('span', 'r82-kv-line', step.reason));
        if (step.requirement_kinds && step.requirement_kinds.length) {
          line.appendChild(el('span', 'r82-kv-line', step.requirement_kinds.join(', ')));
        }
        actions.appendChild(line);
      });
    }
    body.appendChild(actions);
  }

  function renderHumanReview(body, workbench) {
    var review = workbench.human_review || {};
    var conflicts = workbench.conflicts || {};
    var box = el('div', review.required ? 'r82-review r82-review-required' : 'r82-review');
    box.appendChild(el('p', 'r82-state-title', review.required ? 'HUMAN REVIEW REQUIRED' : 'No human review required'));
    if (review.reasons && review.reasons.length) {
      var row = el('div', 'r82-chip-row');
      review.reasons.forEach(function (reason) {
        row.appendChild(chip(reason, 'r82-chip-review'));
      });
      box.appendChild(row);
    }
    if (conflicts.count) {
      box.appendChild(el('p', 'r82-kv-line', 'Conflicts: ' + String(conflicts.count) + ' · NOT RESOLVED'));
    }
    body.appendChild(box);
  }

  function renderHypotheses(body, workbench) {
    var items = workbench.hypotheses || [];
    if (!items.length) {
      body.appendChild(el('p', 'r82-empty', 'no hypotheses'));
      return;
    }
    var table = el('table', 'tbl tbl-compact r82-tbl');
    var head = document.createElement('thead');
    var headRow = document.createElement('tr');
    ['Ref', 'Title', 'Category', 'Priority', 'Confidence', 'Evidence', 'Research'].forEach(function (label) {
      headRow.appendChild(el('th', null, label));
    });
    head.appendChild(headRow);
    table.appendChild(head);
    var tbody = document.createElement('tbody');
    items.forEach(function (item) {
      var row = document.createElement('tr');
      row.appendChild(el('td', null, item.hypothesis_ref || '—'));
      row.appendChild(el('td', null, item.title || '—'));
      row.appendChild(el('td', null, item.category || '—'));
      row.appendChild(el('td', null, item.priority || '—'));
      row.appendChild(el('td', null, item.confidence || '—'));
      row.appendChild(el('td', null, item.evidence_state || '—'));
      row.appendChild(el('td', null, item.hypothesis_state || '—'));
      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    body.appendChild(table);
  }

  function renderWhy(body, workbench) {
    var why = workbench.why_interesting || {};
    if (why.state !== 'AVAILABLE' || !why.reasons || !why.reasons.length) {
      body.appendChild(el('p', 'r82-empty', 'no bounded rationale available'));
      return;
    }
    body.appendChild(list(why.reasons));
  }

  function renderConflicts(body, workbench) {
    var conflicts = workbench.conflicts || {};
    if (!conflicts.count) {
      body.appendChild(el('p', 'r82-empty', 'no conflicts'));
      return;
    }
    body.appendChild(el('p', 'r82-kv-line', 'Conflict count: ' + String(conflicts.count)));
    body.appendChild(el('p', 'r82-kv-line', 'Human review required: ' + boolText(conflicts.human_review_required)));
    body.appendChild(el('p', 'r82-kv-line', 'Resolution: NOT RESOLVED (no automatic winner)'));
    var preserved = conflicts.preserved || [];
    preserved.forEach(function (entry) {
      var row = el('div', 'r82-conflict');
      row.appendChild(el('p', 'r82-req-kind', entry.requirement_kind || 'requirement'));
      row.appendChild(el('p', 'r82-kv-line', 'Relationship: ' + (entry.relation_to_previous || '—')));
      if (entry.existing_evidence_refs && entry.existing_evidence_refs.length) {
        row.appendChild(el('p', 'r82-kv-line', 'Existing: ' + entry.existing_evidence_refs.join(', ')));
      }
      if (entry.new_evidence_refs && entry.new_evidence_refs.length) {
        row.appendChild(el('p', 'r82-kv-line', 'New: ' + entry.new_evidence_refs.join(', ')));
      }
      body.appendChild(row);
    });
  }

  function renderHistory(body, workbench) {
    var history = workbench.history || [];
    if (!history.length) {
      body.appendChild(el('p', 'r82-empty', 'no iterations recorded'));
      return;
    }
    var table = el('table', 'tbl tbl-compact r82-tbl');
    var head = document.createElement('thead');
    var headRow = document.createElement('tr');
    ['#', 'Status', 'Readiness', 'Decision', 'Feedback', 'Hypothesis', 'Next', 'Accepted', 'Conflicts'].forEach(function (label) {
      headRow.appendChild(el('th', null, label));
    });
    head.appendChild(headRow);
    table.appendChild(head);
    var tbody = document.createElement('tbody');
    history.forEach(function (entry) {
      var row = document.createElement('tr');
      row.appendChild(el('td', null, entry.iteration_number || '—'));
      row.appendChild(el('td', null, entry.status || '—'));
      row.appendChild(el('td', null, entry.sufficiency_state || '—'));
      row.appendChild(el('td', null, entry.decision_state || '—'));
      row.appendChild(el('td', null, entry.feedback_state || '—'));
      row.appendChild(el('td', null, entry.hypothesis_state || '—'));
      row.appendChild(el('td', null, entry.next_iteration || '—'));
      row.appendChild(el('td', null, String(entry.accepted_evidence_count || 0)));
      row.appendChild(el('td', null, String(entry.conflict_count || 0)));
      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    body.appendChild(table);
    if (workbench.history_truncated) {
      body.appendChild(el('p', 'r82-kv-line', 'History truncated to the bounded R76 window.'));
    }
  }

  function renderSafety(body, workbench) {
    var safety = workbench.safety || {};
    var rows = [
      ['Advisory', boolText(safety.advisory)],
      ['Research only', boolText(safety.research_only)],
      ['Execution performed', boolText(safety.execution_performed)],
      ['Vulnerability confirmed', boolText(safety.vulnerability_confirmed)],
      ['Exploit authorized', boolText(safety.exploit_authorized)],
      ['Confirmation state', safety.confirmation_state || 'NOT_CONFIRMED'],
      ['Human authority required', boolText(safety.human_authority_required)]
    ];
    var grid = el('div', 'r82-safety');
    rows.forEach(function (pair) {
      var cell = el('div', 'r82-safety-item');
      cell.appendChild(el('p', 'r82-kv-label', pair[0]));
      cell.appendChild(el('p', 'r82-kv-value', pair[1]));
      grid.appendChild(cell);
    });
    body.appendChild(grid);
  }

  function renderWorkbench(workbench, summary) {
    var container = document.getElementById('workbench');
    if (!container) return;
    clear(container);

    var current = { container: container };
    renderCurrentState(section(current, 'Current state (derived)', 'section-current-state'), workbench, summary);
    renderWhatWeKnow(section(current, 'What we know (evidence)', 'section-what-we-know'), workbench);
    renderWhatIsMissing(section(current, 'What is missing (requirements)', 'section-what-is-missing'), workbench);
    renderNext(section(current, 'What to do next', 'section-what-to-do-next'), workbench);
    renderHumanReview(section(current, 'Human review (human-only)', 'section-human-review'), workbench);
    renderHypotheses(section(current, 'Hypotheses (model/research output)', 'section-hypotheses'), workbench);
    renderWhy(section(current, 'Why interesting', 'section-why-interesting'), workbench);
    renderConflicts(section(current, 'Conflicts', 'section-conflicts'), workbench);
    renderHistory(section(current, 'History', 'section-history'), workbench);
    renderSafety(section(current, 'Safety', 'section-safety'), workbench);
  }

  function renderCaseHeader(summary, program) {
    var title = document.getElementById('case-title');
    if (title) title.textContent = summary.case_id || 'research case';
    var meta = document.getElementById('case-meta');
    if (meta) {
      clear(meta);
      meta.appendChild(chip('program: ' + (program || summary.program || '—')));
      meta.appendChild(chip('category: ' + (summary.category || '—')));
      meta.appendChild(chip('gap: ' + (summary.gap_id || '—')));
      meta.appendChild(statusBadge(summary.status));
      meta.appendChild(readinessBadge(summary.sufficiency_state));
    }
    var back = document.getElementById('case-back');
    if (back) {
      back.href = 'index.html' + (apiKey() ? '?api_key=' + encodeURIComponent(apiKey()) : '');
    }
    var home = document.getElementById('case-home');
    if (home) home.href = homeUrl();
  }

  function requestRequirementKinds(request) {
    if (!request || request.request_state !== 'EVIDENCE_REQUESTED') return [];
    return (request.requirements || [])
      .map(function (entry) { return entry.requirement_kind; })
      .filter(function (kind) { return !!kind; });
  }

  function fillEvidenceForm(snapshot, summary, request) {
    var select = document.getElementById('evidence-requirement');
    if (!select) return;
    clear(select);
    // R96: prefer the R95 request requirements (the operator-facing
    // hand-off); fall back to the unchanged R77 missing lists.
    var kinds = requestRequirementKinds(request);
    if (!kinds.length) kinds = (snapshot && snapshot.missingAll) || [];
    if (!kinds.length) kinds = (snapshot && snapshot.missing) || [];
    if (!kinds.length) {
      var option = el('option', null, 'no missing requirements');
      option.value = '';
      select.appendChild(option);
    } else {
      kinds.forEach(function (kind) {
        var option = el('option', null, kind);
        option.value = kind;
        select.appendChild(option);
      });
    }
    var datalist = document.getElementById('evidence-hypotheses');
    if (datalist) {
      clear(datalist);
      var refs = (request && request.hypothesis_refs) || [];
      refs.forEach(function (ref) {
        var refOption = el('option', null, ref);
        refOption.value = ref;
        datalist.appendChild(refOption);
      });
    }
  }

  function useRequestItem(kind) {
    var select = document.getElementById('evidence-requirement');
    if (select) select.value = kind;
    var note = document.getElementById('evidence-request-note');
    if (note && currentRequest) {
      note.textContent =
        'request ' + (currentRequest.request_ref || '') +
        ' · requirement ' + kind +
        ' · source HUMAN_REVIEW — fill the observation yourself';
    }
    var refInput = document.querySelector('input[name="evidence-ref"]');
    if (refInput) refInput.focus();
  }

  function renderEvidenceRequest(request, summary) {
    var host = document.getElementById('evidence-request');
    if (!host) return;
    clear(host);
    currentRequest = request || null;
    var panel = el('section', 'panel r82-panel');
    var head = el('div', 'panel-head');
    head.appendChild(
      el('h2', null, 'Evidence request (R95 — requested, not evidence)')
    );
    panel.appendChild(head);
    var body = el('div', 'panel-body');
    if (!request) {
      body.appendChild(
        el('p', 'r82-empty', 'No operator-facing evidence request is available (fail closed).')
      );
      panel.appendChild(body);
      host.appendChild(panel);
      return;
    }
    body.appendChild(el('p', 'r82-kv-line',
      'Request: ' + (request.request_ref || '—') +
      ' · state ' + (request.request_state || '—') +
      ' · next ' + (request.next_action || '—')));
    body.appendChild(el('p', 'r82-kv-line',
      'Human action required: ' + boolText(request.human_action_required) +
      ' · offline sources exhausted: ' + boolText(request.offline_sources_exhausted)));
    if (request.request_state !== 'EVIDENCE_REQUESTED') {
      body.appendChild(el('p', 'r82-empty', request.reason || 'No evidence request is required.'));
    } else {
      (request.requirements || []).forEach(function (entry) {
        var box = el('div', 'r82-requirement');
        box.appendChild(el('p', 'r82-req-kind',
          entry.requirement_kind + ' [' + (entry.requirement_class || '—') + ']'));
        box.appendChild(el('p', 'r82-kv-line',
          'Status: ' + (entry.status || '—') +
          ' · acquisition: ' + (entry.acquisition_type || '—') +
          ' · offline exhausted: ' + boolText(entry.offline_exhausted)));
        box.appendChild(el('p', 'r82-kv-line', 'Expected output: ' + (entry.expected_output || '—')));
        box.appendChild(el('p', 'r82-kv-line', 'Completion: ' + (entry.completion_condition || '—')));
        if (entry.hypothesis_refs && entry.hypothesis_refs.length) {
          box.appendChild(el('p', 'r82-kv-line', 'Valid hypothesis refs: ' + entry.hypothesis_refs.join(', ')));
        }
        var use = el('button', 'btn-secondary', 'Use in submission');
        use.type = 'button';
        use.addEventListener('click', function () { useRequestItem(entry.requirement_kind); });
        box.appendChild(use);
        body.appendChild(box);
      });
      body.appendChild(el('p', 'r82-kv-label', 'Provenance requirements (unchanged R80/R89 boundary)'));
      (request.provenance_requirements || []).forEach(function (entry) {
        body.appendChild(el('p', 'r82-kv-line', '· ' + entry));
      });
      body.appendChild(el('p', 'r82-kv-label', 'Safety boundary'));
      (request.safety_boundary || []).forEach(function (entry) {
        body.appendChild(el('p', 'r82-kv-line', '· ' + entry));
      });
      body.appendChild(el('p', 'r82-kv-line',
        'The R80 envelope template stays empty here; the human supplies the ' +
        'observation. A read-only template is available via ' +
        'agent acquisitions --request --json.'));
    }
    panel.appendChild(body);
    host.appendChild(panel);
  }

  async function refreshEvidenceRequest(caseId) {
    var result = await apiFetch(API_CASES + '/' + encodeURIComponent(caseId));
    if (result.state !== 'ok' || !result.body) return;
    var request = result.body.evidence_request || null;
    renderEvidenceRequest(request, result.body.case_summary || {});
    fillEvidenceForm(
      snapshotFromWorkbench(result.body.workbench || {}),
      result.body.case_summary || {},
      request
    );
  }

  function snapshotFromWorkbench(workbench) {
    var state = workbench.current_state || {};
    var known = workbench.what_we_know || {};
    var missing = workbench.what_is_missing || {};
    return {
      status: state.status || '',
      readiness: state.readiness || '',
      decision: state.decision || '',
      know: (known.available_requirement_kinds || []).slice(),
      missing: (missing.decision_critical_missing || []).slice(),
      missingAll: (missing.missing_requirement_kinds || []).slice(),
      review: !!state.human_review_required
    };
  }

  function changesBetween(before, after) {
    var changes = [];
    if (before.status !== after.status) {
      changes.push('Status: ' + before.status + ' → ' + after.status);
    }
    if (before.readiness !== after.readiness) {
      changes.push('Readiness: ' + before.readiness + ' → ' + after.readiness);
    }
    if (before.decision !== after.decision) {
      changes.push('Decision: ' + before.decision + ' → ' + after.decision);
    }
    var added = after.know.filter(function (kind) { return before.know.indexOf(kind) === -1; });
    if (added.length) changes.push('Evidence gained: ' + added.join(', '));
    var resolved = before.missing.filter(function (kind) { return after.missing.indexOf(kind) === -1; });
    if (resolved.length) changes.push('No longer missing: ' + resolved.join(', '));
    if (!before.review && after.review) changes.push('Human review: not required → required');
    if (before.review && !after.review) changes.push('Human review: required → not required');
    return changes;
  }

  function renderSubmissionResult(result, changes) {
    var box = document.getElementById('submission-result');
    if (!box) return;
    clear(box);
    box.hidden = false;
    var ok = result.submission_status === 'ACCEPTED' || result.submission_status === 'PARTIAL';
    var replayed = result.submission_status === 'REPLAYED';
    var head = el('div', ok || replayed ? 'r82-result r82-result-ok' : 'r82-result r82-result-warn');
    head.appendChild(
      el('p', 'r82-state-title', 'Human submission ' + (result.submission_status || 'processed'))
    );
    head.appendChild(el('p', 'r82-kv-line', 'Accepted evidence: ' + String(result.accepted_external_evidence || 0)));
    if (result.persistence) {
      head.appendChild(
        el('p', 'r82-kv-line', 'Persisted to case artifact: ' + boolText(result.persistence.written))
      );
    }
    if (result.rejection_codes && result.rejection_codes.length) {
      var row = el('div', 'r82-chip-row');
      result.rejection_codes.forEach(function (code) {
        row.appendChild(chip(code, 'r82-chip-missing'));
      });
      head.appendChild(row);
    }
    if (result.provenance) {
      head.appendChild(
        el(
          'p',
          'r82-kv-line',
          'Conflicts: ' + String(result.provenance.conflict_count || 0) +
            ' · review required: ' + boolText(result.provenance.human_review_required)
        )
      );
    }
    box.appendChild(head);
    if (changes && changes.length) {
      var changeBox = el('div', 'r82-changes');
      changeBox.appendChild(el('p', 'r82-kv-label', 'What changed'));
      changes.forEach(function (line) {
        changeBox.appendChild(el('p', 'r82-kv-line', line));
      });
      box.appendChild(changeBox);
    }
  }

  function renderSubmissionError(code, status) {
    var box = document.getElementById('submission-result');
    if (!box) return;
    clear(box);
    box.hidden = false;
    var error = el('div', 'r82-result r82-result-err');
    error.appendChild(el('p', 'r82-state-title', 'Submission rejected'));
    error.appendChild(el('p', 'r82-kv-line', 'HTTP ' + String(status || '') + ' · ' + (code || 'unknown code')));
    if (code && REJECTION_HINTS[code]) {
      error.appendChild(el('p', 'r82-kv-line', REJECTION_HINTS[code]));
    }
    box.appendChild(error);
  }

  function parseObservation(form) {
    var ref = form.elements['evidence-ref'].value.trim();
    var fact = form.elements['evidence-fact'].value.trim();
    var effect = form.elements['evidence-effect'].value;
    var item = {
      hypothesis_ref: form.elements['evidence-hypothesis'].value.trim() || 'H1',
      requirement_kind: form.elements['evidence-requirement'].value,
      effect: effect,
      source: form.elements['evidence-source'].value,
      evidence_ref: ref
    };
    if (effect === 'INVALIDATES') {
      item.invalidates_refs = [ref];
    } else {
      item.observations = [{ ref: ref, fact: fact }];
    }
    return item;
  }

  function initEvidenceForm(caseId, snapshot) {
    var form = document.getElementById('evidence-form');
    if (!form) return;
    var before = snapshot;
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      var item = parseObservation(form);
      var body = {
        submission_version: 'r80-1',
        case_ref: caseId,
        submitted_by: form.elements['evidence-submitter']
          ? form.elements['evidence-submitter'].value.trim()
          : '',
        items: [item]
      };
      var result = await apiFetch(
        API_CASES + '/' + encodeURIComponent(caseId) + '/human-evidence',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        }
      );
      if (result.state === 'ok' && result.body) {
        var workbench = result.body.workbench || {};
        var after = snapshotFromWorkbench(workbench);
        var changes = changesBetween(before, after);
        renderSubmissionResult(result.body, changes);
        renderWorkbench(workbench, result.body.case_summary || {});
        fillEvidenceForm(after, result.body.case_summary || {}, currentRequest);
        before = after;
        await refreshEvidenceRequest(caseId);
        return;
      }
      if (result.state === 'rejected') {
        renderSubmissionError(result.code, result.status);
        return;
      }
      renderSubmissionError(result.state.toUpperCase(), result.status);
    });
  }

  async function initCaseDetail() {
    var container = document.getElementById('case-detail-state');
    var caseId = caseIdFromUrl();
    if (!caseId) {
      showState(container, 'error', 'Missing case_id', 'Open this page from the case list.');
      return;
    }
    showState(container, 'loading', 'Loading case ' + caseId + '…');
    var result = await apiFetch(API_CASES + '/' + encodeURIComponent(caseId));
    if (result.state !== 'ok' || !result.body) {
      showState(
        container,
        result.state === 'unauthorized'
          ? 'unauthorized'
          : result.state === 'not-found'
            ? 'error'
            : 'error',
        result.state === 'unauthorized'
          ? 'API key required'
          : result.state === 'not-found'
            ? 'Unknown case'
            : result.state === 'unavailable'
              ? 'API unavailable'
              : 'Could not load case',
        result.code || ''
      );
      return;
    }
    hideState(container);
    var body = result.body;
    var workbench = body.workbench || {};
    renderCaseHeader(body.case_summary || {}, body.program);
    renderWorkbench(workbench, body.case_summary || {});
    renderEvidenceRequest(body.evidence_request || null, body.case_summary || {});
    var snapshot = snapshotFromWorkbench(workbench);
    fillEvidenceForm(snapshot, body.case_summary || {}, body.evidence_request || null);
    initEvidenceForm(caseId, snapshot);
    var refresh = document.getElementById('case-refresh');
    if (refresh) {
      refresh.addEventListener('click', function () {
        initCaseDetail();
      });
    }
  }


  // =====================================================================
  // AI ACTIVITY / RUNTIME STATUS (R83, read-only)
  // =====================================================================

  var ACTIVITY_STATUS_CLASS = {
    RUNNING: 'badge-running',
    WAITING_FOR_EVIDENCE: 'badge-neutral',
    COMPLETED: 'badge-ok',
    COMPLETED_WITH_REJECTIONS: 'badge-warn',
    ERROR: 'badge-err',
    IDLE: 'badge-idle',
    UNKNOWN: 'badge-idle'
  };

  function formatDuration(seconds) {
    if (seconds === null || seconds === undefined || seconds === '') return '—';
    var value = Number(seconds);
    if (!isFinite(value) || value < 0) return '—';
    if (value < 60) return value.toFixed(1) + 's';
    var minutes = Math.floor(value / 60);
    var rest = Math.round(value - minutes * 60);
    if (minutes < 60) return minutes + 'm ' + rest + 's';
    var hours = Math.floor(minutes / 60);
    return hours + 'h ' + (minutes - hours * 60) + 'm';
  }

  function shortTime(iso) {
    if (!iso) return '—';
    return String(iso).replace('T', ' ');
  }

  function activityStatusBadge(status) {
    return badge(status || 'UNKNOWN', ACTIVITY_STATUS_CLASS[status] || 'badge-idle');
  }

  function activityLine(container, label, value) {
    var line = el('p', 'r82-kv-line');
    line.appendChild(el('span', 'r82-kv-label', label + ': '));
    line.appendChild(el('span', null, value === null || value === undefined || value === '' ? '—' : String(value)));
    container.appendChild(line);
  }

  function renderActivity(body) {
    var status = body.status || 'UNKNOWN';
    var statusSlot = document.getElementById('activity-status');
    if (statusSlot) {
      clear(statusSlot);
      statusSlot.appendChild(activityStatusBadge(status));
    }
    var timeSlot = document.getElementById('activity-time');
    if (timeSlot) timeSlot.textContent = shortTime(body.server_time_tehran);
    var windowBlock = body.window || {};
    var windowLabel = document.getElementById('activity-window');
    if (windowLabel) {
      windowLabel.textContent = 'window: ' + (windowBlock.start || '—') + '-' + (windowBlock.end || '—') + ' ' + (windowBlock.timezone || '');
    }
    var windowSlot = document.getElementById('activity-window-label');
    if (windowSlot) {
      windowSlot.textContent = (windowBlock.start || '—') + '-' + (windowBlock.end || '—') + ' ' + (windowBlock.timezone || '');
    }
    var inWindowSlot = document.getElementById('activity-in-window');
    if (inWindowSlot) inWindowSlot.textContent = boolText(windowBlock.in_window);

    var lastRun = document.getElementById('activity-last-run');
    if (lastRun) {
      clear(lastRun);
      var run = body.last_run;
      lastRun.appendChild(el('p', 'r82-kv-label', 'Last run'));
      if (!run) {
        lastRun.appendChild(el('p', 'r82-empty', 'no persisted run record'));
      } else {
        activityLine(lastRun, 'Run', run.run_id);
        activityLine(lastRun, 'Status', run.status + ' (' + (run.agent_status || '') + ')' + (run.skipped ? ' skipped=' + run.skipped : ''));
        activityLine(lastRun, 'Started', shortTime(run.started_at));
        activityLine(lastRun, 'Finished', shortTime(run.finished_at));
        activityLine(lastRun, 'Duration', formatDuration(run.duration_seconds));
        activityLine(lastRun, 'Plans', String(run.plans_processed || 0) + ' / selected ' + String(run.plans_selected || 0));
        activityLine(lastRun, 'Results', String(run.result_count || 0));
        activityLine(lastRun, 'Evidence / sources', String(run.evidence_count || 0) + ' / ' + String(run.sources_count || 0));
        if (run.cve_id || run.program) {
          activityLine(lastRun, 'Program', (run.program || '—') + ' ' + (run.cve_id || ''));
        }
        activityLine(lastRun, 'Failures', String(run.failure_count || 0));
      }
    }

    var currentCase = document.getElementById('activity-current-case');
    if (currentCase) {
      clear(currentCase);
      currentCase.appendChild(el('p', 'r82-kv-label', 'Current case'));
      var entry = body.current_case;
      if (!entry) {
        currentCase.appendChild(el('p', 'r82-empty', 'no research case artifact'));
      } else {
        activityLine(currentCase, 'Case', entry.case_id);
        activityLine(currentCase, 'Program / category', (entry.program || '—') + ' / ' + (entry.category || '—'));
        activityLine(currentCase, 'Case state', entry.case_status + ' · ' + entry.sufficiency_state + ' · ' + entry.decision_state);
        activityLine(currentCase, 'Evidence available / missing', String(entry.available_count || 0) + ' / ' + String(entry.missing_count || 0));
        activityLine(currentCase, 'Stage', body.current_stage || 'unknown (not persisted by the agent)');
      }
    }

    var daily = document.getElementById('activity-daily');
    if (daily) {
      clear(daily);
      var summary = body.daily || {};
      daily.appendChild(el('p', 'r82-kv-label', 'Daily window summary'));
      activityLine(daily, 'Window', summary.window || '—');
      activityLine(daily, 'Runs', summary.runs);
      activityLine(daily, 'Plans processed', summary.plans_processed);
      activityLine(daily, 'Results', summary.results);
      activityLine(daily, 'Evidence acquired', summary.evidence_acquired);
      activityLine(daily, 'Cases processed', summary.cases_processed);
      activityLine(daily, 'Accepted / rejected hypotheses', String(summary.accepted_hypotheses || 0) + ' / ' + String(summary.rejected_hypotheses || 0));
      activityLine(daily, 'Evidence available / missing', String(summary.evidence_available || 0) + ' / ' + String(summary.evidence_missing || 0));
      activityLine(daily, 'Actions generated', summary.actions_generated);
      var totals = body.totals || {};
      activityLine(daily, 'Totals (all persisted)', 'runs=' + String(totals.runs || 0) + ' results=' + String(totals.results || 0) + ' cases=' + String(totals.cases || 0));
    }

    var errorSlot = document.getElementById('activity-error');
    if (errorSlot) {
      clear(errorSlot);
      if (body.last_error) {
        errorSlot.appendChild(el('p', 'r82-kv-label', 'Last error'));
        errorSlot.appendChild(el('p', 'r82-kv-line', body.last_error));
      }
    }

    var note = document.getElementById('activity-note');
    if (note) {
      var observability = body.observability || {};
      var parts = [];
      parts.push('basis: ' + (body.status_basis || '—'));
      if (observability.unavailable_fields && observability.unavailable_fields.length) {
        parts.push('unavailable: ' + observability.unavailable_fields.join(', '));
      }
      parts.push('UNKNOWN means the runtime state could not be observed; it does not mean failure.');
      note.textContent = parts.join(' · ');
    }
  }

  async function initActivity() {
    var container = document.getElementById('activity-state');
    if (!container) return;
    showState(container, 'loading', 'Loading AI activity…');
    var result = await apiFetch('/api/research/activity');
    if (result.state !== 'ok' || !result.body) {
      showState(
        container,
        result.state === 'unauthorized' ? 'unauthorized' : 'error',
        result.state === 'unauthorized'
          ? 'API key required'
          : result.state === 'unavailable'
            ? 'API unavailable'
            : 'Could not load AI activity',
        result.code || ''
      );
      return;
    }
    hideState(container);
    renderActivity(result.body);
    var refresh = document.getElementById('activity-refresh');
    if (refresh && !refresh.dataset.bound) {
      refresh.dataset.bound = '1';
      refresh.addEventListener('click', function () {
        initActivity();
      });
    }
  }

  // ---------- bootstrap ----------
  document.addEventListener('DOMContentLoaded', function () {
    var page = document.body.getAttribute('data-r82-page');
    var home = document.getElementById('page-home');
    if (home) home.href = homeUrl();
    if (page === 'case-list') {
      initCaseList();
      initActivity();
    } else if (page === 'case-detail') {
      initCaseDetail();
    }
  });

  window.ResearchDashboard = {
    apiKey: apiKey,
    withKey: withKey,
    apiFetch: apiFetch,
    statusBadge: statusBadge,
    renderCaseList: renderListRows,
    renderWorkbench: renderWorkbench,
    renderEvidenceRequest: renderEvidenceRequest,
    renderActivity: renderActivity,
    initCaseList: initCaseList,
    initActivity: initActivity,
    initCaseDetail: initCaseDetail
  };
})();
