"""Hermes autofill vault — read-only viewer + delete, inside the watch dashboard.

Hermes ships no web UI for its vault, so this surfaces item *metadata* (handles,
kind, label, origin, identifier, whether a TOTP seed exists). Secret values are
never read or shown. Adding credentials is intentionally NOT exposed here: the
dashboard is plain HTTP on a public bind, so new secrets should be entered via
the ``hermes vault add`` CLI where the plaintext never crosses the network.
"""
import html
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from backend import hermes_vault
from backend.helpers import build_url, render_page

router = APIRouter()


def _esc(value):
    return html.escape(str(value or ""))


def _kind_badge(kind):
    colors = {"login": "#58a6ff", "payment": "#d29922", "address": "#8b949e"}
    color = colors.get(kind, "#8b949e")
    return f'<span class="badge" style="border-color:{color};color:{color};">{_esc(kind)}</span>'


@router.get("/ui/vault", response_class=HTMLResponse)
def ui_vault(request: Request):
    ok = request.query_params.get("ok")
    err = request.query_params.get("err")

    banner = ""
    if ok:
        banner += f'<p class="note" style="color:#3fb950;">{_esc(ok)}</p>'
    if err:
        banner += f'<p class="note" style="color:#f85149;">{_esc(err)}</p>'

    try:
        items = hermes_vault.list_items()
        load_error = None
    except hermes_vault.VaultUnavailable as exc:
        items, load_error = [], str(exc)

    rows = ""
    for it in items:
        ident = it.get("identifier")
        ident_cell = (f'{_esc(ident)} <span class="note">({_esc(it.get("identifier_type"))})</span>'
                      if ident else "—")
        origins = it.get("allowed_origins")
        origin_cell = _esc(it.get("origin") or "—")
        if origins and len(origins) > 1:
            origin_cell += f' <span class="note">+{len(origins) - 1} more</span>'
        otp = '<span class="badge" style="border-color:#3fb950;color:#3fb950;">TOTP</span>' if it.get("has_otp") else "—"
        handle = _esc(it.get("id"))
        confirm_js = (f"return confirm('Remove vault item {handle}? "
                      "This deletes the stored secret permanently.')")
        rows += (
            f'<tr><td data-label="Kind">{_kind_badge(it.get("kind"))}</td>'
            f'<td class="name" data-label="Label">{_esc(it.get("label"))}</td>'
            f'<td data-label="Identifier">{ident_cell}</td>'
            f'<td data-label="Origin">{origin_cell}</td>'
            f'<td data-label="2FA">{otp}</td>'
            f'<td class="ts" data-label="Created">{_esc(it.get("created_at"))}</td>'
            f'<td data-label="Actions"><form method="post" action="/ui/vault/remove" '
            f'onsubmit="{confirm_js}" style="margin:0;">'
            f'<input type="hidden" name="item_id" value="{handle}">'
            f'<button type="submit">Remove</button></form></td></tr>'
        )

    if load_error:
        rows = f'<tr><td colspan="7" class="note">Vault unavailable: {_esc(load_error)}</td></tr>'
    elif not rows:
        rows = ('<tr><td colspan="7" class="note">Vault is empty. '
                'Add items with <code>hermes vault add</code> on the host.</td></tr>')

    home = build_url("/")
    body = f"""
    <a href="{home}">← Back to Dashboard</a>
    <h2>Hermes Vault</h2>
    {banner}
    <p class="note">Read-only view of the Hermes autofill vault
    (<code>~/.hermes/vault</code>). Metadata only — secret values are never shown here.
    Add credentials with <code>hermes vault add</code> (the dashboard is plain HTTP, so
    secrets are never entered over the web). Removing an item deletes its stored secret.</p>
    <div class="table-wrap"><table class="status">
      <thead><tr>
        <th>Kind</th><th>Label</th><th>Identifier</th><th>Origin</th>
        <th>2FA</th><th>Created</th><th>Actions</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
    """
    return HTMLResponse(render_page("Hermes Vault", body))


@router.post("/ui/vault/remove")
async def remove_vault_item(request: Request):
    form = await request.form()
    item_id = (form.get("item_id") or "").strip()
    if not item_id:
        return RedirectResponse("/ui/vault?err=" + quote("missing item handle"), status_code=303)
    try:
        removed = hermes_vault.remove_item(item_id)
    except hermes_vault.VaultUnavailable as exc:
        return RedirectResponse("/ui/vault?err=" + quote(str(exc)), status_code=303)
    if removed:
        return RedirectResponse("/ui/vault?ok=" + quote(f"removed {item_id}"), status_code=303)
    return RedirectResponse("/ui/vault?err=" + quote(f"no vault item with handle {item_id}"), status_code=303)
