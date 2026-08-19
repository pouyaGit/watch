from flask import Flask, request
from datetime import datetime, timedelta
from urllib.parse import urlparse
import sys, os, tldextract
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'database')))
from db import *

app = Flask(__name__)

def normalize_domain(input_str: str) -> str:
    if '://' in input_str:
        parsed = urlparse(input_str)
        input_str = parsed.netloc or parsed.path.split('/')[0]
    input_str = input_str.rstrip('/')
    if input_str.startswith('www.'):
        input_str = input_str[4:]
    extracted = tldextract.extract(input_str)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return input_str.strip().lower()


def make_html_list(items, title="Results"):
    if not items:
        return f"<h3>{title}</h3><p>No results found.</p><br><a href='/'>← Back to Index</a>"

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>
        body {{ font-family: monospace; background: #0f0f0f; color: #00ff9d; padding: 20px; }}
        a {{ color: #00bfff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; color: #ff6b6b; }}
        h2 {{ color: #ffcc00; }}
        .count {{ color: #aaa; margin-bottom: 15px; }}
        li {{ margin: 4px 0; }}
    </style>
</head>
<body>
    <h2>{title}</h2>
    <div class="count">Total: {len(items)} items</div>
    <ul>
"""
    for item in items:
        if item.startswith("http"):
            html += f'<li><a href="{item}" target="_blank" rel="noopener">{item}</a></li>\n'
        else:
            html += f'<li><a href="https://{item}" target="_blank" rel="noopener">{item}</a></li>\n'

    html += """
    </ul>
    <br>
    <a href="/">← Back to Index</a>
</body>
</html>
"""
    return html


@app.route('/')
def index():
    programs = list(Programs.objects().all())
    providers = ["subfinder", "crtsh", "findomain", "assetfinder", "amass", "abuseipdb", "waybackurls"]

    # Programs
    programs_html = '<a href="/api/programs/all" target="_blank">/api/programs/all</a>'

    # HTTP
    http_html = '''
        <a href="/api/http/all" target="_blank">/api/http/all</a>
        <a href="/api/http/fresh" target="_blank">/api/http/fresh (24h)</a>
        <br><br>
    '''

    for program in programs:
        http_html += f'<div style="margin-top:16px;"><b style="color:#58a6ff;">{program.program_name}</b></div>'

        # Providers per program
        http_html += '<div style="margin:6px 0 4px 8px;color:#8b949e;">Providers:</div>'
        http_html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-left:8px;margin-bottom:10px;">'
        for p in providers:
            http_html += f'<a href="/api/http/provider/{program.program_name}/{p}" target="_blank" style="padding:4px 10px;">{p}</a>'
        http_html += '</div>'

        # Technologies
        techs = set()
        for h in Http.objects(program_name=program.program_name).only('tech'):
            if h.tech:
                for t in h.tech:
                    if t and t.strip():
                        techs.add(t.strip())
        if techs:
            http_html += '<div style="margin:8px 0 4px 8px;color:#8b949e;">Technologies:</div>'
            http_html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-left:8px;margin-bottom:12px;">'
            for tech in sorted(techs):
                http_html += f'<a href="/api/http/tech/{program.program_name}/{tech}" target="_blank" style="padding:4px 10px;background:#21262d;">{tech}</a>'
            http_html += '</div>'

    # Subdomains
    sub_html = '<a href="/api/subdomains/all" target="_blank">/api/subdomains/all</a><br><br>'
    for program in programs:
        sub_html += f'<div style="margin-top:14px;"><b style="color:#58a6ff;">{program.program_name}</b></div>'
        sub_html += f'<a href="/api/subdomains/program/{program.program_name}" target="_blank">/api/subdomains/program/{program.program_name}</a>'
        sub_html += '<div style="margin:6px 0 4px 8px;color:#8b949e;">Domains:</div>'
        sub_html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-left:8px;">'
        for scope in program.scopes:
            if scope and scope.strip():
                sub_html += f'<a href="/api/subdomains/domain/{scope}" target="_blank" style="padding:4px 10px;">{scope}</a>'
        sub_html += '</div>'

    # Lives
    lives_html = '''
        <a href="/api/lives/all" target="_blank">/api/lives/all</a>
        <a href="/api/lives/fresh" target="_blank">/api/lives/fresh (24h)</a>
        <br><br>
    '''
    for program in programs:
        lives_html += f'<div style="margin-top:14px;"><b style="color:#58a6ff;">{program.program_name}</b></div>'
        lives_html += f'<a href="/api/lives/program/{program.program_name}" target="_blank">/api/lives/program/{program.program_name}</a>'

        lives_html += '<div style="margin:6px 0 4px 8px;color:#8b949e;">Domains:</div>'
        lives_html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-left:8px;margin-bottom:8px;">'
        for scope in program.scopes:
            if scope and scope.strip():
                lives_html += f'<a href="/api/lives/domain/{scope}" target="_blank" style="padding:4px 10px;">{scope}</a>'
        lives_html += '</div>'

        # Providers per program
        lives_html += '<div style="margin:6px 0 4px 8px;color:#8b949e;">Providers:</div>'
        lives_html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-left:8px;">'
        for p in providers:
            lives_html += f'<a href="/api/lives/provider/{program.program_name}/{p}" target="_blank" style="padding:4px 10px;">{p}</a>'
        lives_html += '</div>'

    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Watch API - Index</title>
    <style>
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #0d1117;
            color: #e6edf3;
            max-width: 1100px;
            margin: 40px auto;
            padding: 20px;
        }}
        h1 {{ color: #58a6ff; }}
        a {{
            color: #58a6ff;
            text-decoration: none;
            padding: 6px 12px;
            margin: 3px 0;
            background: #161b22;
            border-radius: 6px;
            border: 1px solid #30363d;
            font-size: 14px;
            display: inline-block;
        }}
        a:hover {{
            background: #1f6feb;
            color: white;
        }}
        .section {{ margin-top: 40px; }}
        .section h2 {{
            color: #f0883e;
            border-bottom: 1px solid #30363d;
            padding-bottom: 6px;
            margin-bottom: 15px;
        }}
        .note {{ color: #8b949e; font-size: 13px; margin-top: 30px; }}
    </style>
</head>
<body>
    <h1>🔍 Watch Bug Bounty API</h1>
    <p>Lightweight dynamic index</p>

    <div class="section">
        <h2>📁 Programs</h2>
        {programs_html}
    </div>

    <div class="section">
        <h2>🌍 HTTP Results</h2>
        {http_html}
    </div>

    <div class="section">
        <h2>🌐 Subdomains</h2>
        {sub_html}
    </div>

    <div class="section">
        <h2>🟢 Live Subdomains</h2>
        {lives_html}
    </div>

    <p class="note">Tip: Add <code>?raw=1</code> to any list endpoint to get plain text.</p>
</body>
</html>
"""


# ====================== PROGRAMS ======================
@app.route('/api/programs/all')
def all_programs():
    programs = Programs.objects().all()
    response = {}
    for program in programs:
        response[program.program_name] = {
            "scopes": program.scopes,
            "ooscopes": program.ooscopes,
            "config": program.config,
            "created_date": program.created_date,
        }
    return response


# ====================== SUBDOMAINS ======================
@app.route('/api/subdomains/all')
def all_subdomains():
    subdomains = [s.subdomain for s in Subdomains.objects().all()]
    if request.args.get('raw') == '1':
        return "\n".join(subdomains)
    return make_html_list(subdomains, "All Subdomains")


@app.route('/api/subdomains/domain/<domain>')
def subdomains_of_domains(domain):
    subdomains = [s.subdomain for s in Subdomains.objects(scope=domain)]
    if not subdomains:
        return f"No subdomains found for domain: {domain}", 404
    if request.args.get('raw') == '1':
        return "\n".join(subdomains)
    return make_html_list(subdomains, f"Subdomains of {domain}")


@app.route('/api/subdomains/program/<p_name>')
def subdomains_of_program(p_name):
    subdomains = [s.subdomain for s in Subdomains.objects(program_name=p_name)]
    if not subdomains:
        return f"No subdomains found for program: {p_name}", 404
    if request.args.get('raw') == '1':
        return "\n".join(subdomains)
    return make_html_list(subdomains, f"Subdomains of program: {p_name}")


# ====================== LIVE SUBDOMAINS ======================
@app.route('/api/lives/fresh')
def all_lives_fresh():
    twenty_four_hours_ago = datetime.now() - timedelta(hours=24)
    items = [s.subdomain for s in LiveSubdomains.objects(created_date__gte=twenty_four_hours_ago)]
    if request.args.get('raw') == '1':
        return "\n".join(items)
    return make_html_list(items, "Fresh Live Subdomains (24h)")


@app.route('/api/lives/all')
def all_lives():
    twelve_hours_ago = datetime.now() - timedelta(hours=12)
    items = [s.subdomain for s in LiveSubdomains.objects(last_update__gte=twelve_hours_ago)]
    if request.args.get('raw') == '1':
        return "\n".join(items)
    return make_html_list(items, "Live Subdomains (last 12h)")


@app.route('/api/lives/program/<p_name>')
def lives_by_program(p_name):
    items = list(LiveSubdomains.objects(program_name=p_name).scalar('subdomain'))
    if not items:
        return f"No live subdomains found for program: {p_name}", 404
    if request.args.get('raw') == '1':
        return "\n".join(items)
    return make_html_list(items, f"Live Subdomains - {p_name}")


@app.route('/api/lives/domain/<path:domain>')
def lives_by_domain(domain):
    clean_domain = normalize_domain(domain)
    items = list(LiveSubdomains.objects(scope=clean_domain).scalar('subdomain'))
    if not items:
        return f"No live subdomains found for domain: {clean_domain}", 404
    if request.args.get('raw') == '1':
        return "\n".join(items)
    return make_html_list(items, f"Live Subdomains - {clean_domain}")


@app.route('/api/lives/provider/<program_name>/<provider>')
def lives_provider_program(program_name, provider):
    subs_obj = Subdomains.objects(program_name=program_name, providers=provider)
    twelve_hours_ago = datetime.now() - timedelta(hours=12)
    items = []
    for sub_obj in subs_obj:
        live = LiveSubdomains.objects(subdomain=sub_obj.subdomain, last_update__gte=twelve_hours_ago).first()
        if live:
            items.append(live.subdomain)
    if request.args.get('raw') == '1':
        return "\n".join(items)
    return make_html_list(items, f"Live Subdomains - {program_name} → Provider: {provider}")


@app.route('/api/live/subdomain/<live>')
def all_live_single(live):
    live_obj = LiveSubdomains.objects(subdomain=live).first()
    subdomain_obj = Subdomains.objects(subdomain=live).first()
    if not live_obj:
        return f"No live subdomain found for: {live}", 404
    return {
        "program_name": live_obj.program_name,
        "subdomain": live_obj.subdomain,
        "scope": live_obj.scope,
        "providers": subdomain_obj.providers if subdomain_obj else [],
        "ips": live_obj.ips or [],
        "cdn": live_obj.cdn,
        "created_date": live_obj.created_date.isoformat() if live_obj.created_date else None,
        "last_update": live_obj.last_update.isoformat() if live_obj.last_update else None,
    }


# ====================== HTTP ======================
@app.route('/api/http/fresh')
def all_http_fresh():
    twenty_four_hours_ago = datetime.now() - timedelta(hours=24)
    items = [h.url for h in Http.objects(created_date__gte=twenty_four_hours_ago)]
    if request.args.get('raw') == '1':
        return "\n".join(items)
    return make_html_list(items, "Fresh HTTP Results (24h)")


@app.route('/api/http/all')
def all_http():
    items = [h.url for h in Http.objects().all()]
    if request.args.get('raw') == '1':
        return "\n".join(items)
    return make_html_list(items, "All HTTP Results")


@app.route('/api/http/provider/<program_name>/<provider>')
def http_provider_program(program_name, provider):
    subs_obj = Subdomains.objects(program_name=program_name, providers=provider)
    twelve_hours_ago = datetime.now() - timedelta(hours=12)
    items = []
    for sub_obj in subs_obj:
        http = Http.objects(subdomain=sub_obj.subdomain, last_update__gte=twelve_hours_ago).first()
        if http:
            items.append(http.url)
    if request.args.get('raw') == '1':
        return "\n".join(items)
    return make_html_list(items, f"HTTP Results - {program_name} → Provider: {provider}")


@app.route('/api/http/tech/<program_name>/<tech>')
def http_by_tech(program_name, tech):
    items = []
    http_objs = Http.objects(program_name=program_name, tech=tech)
    for h in http_objs:
        if h.url:
            items.append(h.url)
    if not items:
        return f"No results found for tech '{tech}' in program '{program_name}'", 404
    if request.args.get('raw') == '1':
        return "\n".join(items)
    return make_html_list(items, f"HTTP Results - {program_name} → Tech: {tech}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)