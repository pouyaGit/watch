from flask import Flask, request
from datetime import datetime, timedelta
from urllib.parse import urlparse
import sys, os, tldextract
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'database')))
from db import *

app = Flask(__name__)

def normalize_domain(input_str: str) -> str:
    """
    هر چیزی که کاربر بده رو به دامنه تمیز تبدیل می‌کنه
    مثال‌ها:
      superbet.ro      → superbet.ro
      superbet.ro/     → superbet.ro
      www.superbet.rs  → superbet.rs
      https://superbet.rs → superbet.rs
      http://superbet.rs/path → superbet.rs
    """
    # اول هر چیزی که شبیه URL باشه رو پارس کن
    if '://' in input_str:
        parsed = urlparse(input_str)
        input_str = parsed.netloc or parsed.path.split('/')[0]  # فقط دامنه رو بگیر
    
    # اسلش آخر رو حذف کن
    input_str = input_str.rstrip('/')
    
    # اگه www. داشت حذفش کن (اختیاری — ولی پیشنهاد میشه)
    if input_str.startswith('www.'):
        input_str = input_str[4:]
    
    # حالا با tldextract دامنه اصلی رو بگیر
    extracted = tldextract.extract(input_str)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return input_str.strip().lower()

# PROGRAM ROUTES
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

# SUBDOMAINS ROUTES
@app.route('/api/subdomains/all')
def all_subdomains():
    subdomains = Subdomains.objects().all()
    response = ''
    for subdomain in subdomains:
        response += f"{subdomain.subdomain}\n"
    return response

@app.route('/api/subdomains/domain/<domain>')
def subdomains_of_domains(domain):
    subdomains = Subdomains.objects(scope=domain)
    if subdomains:
        response = ''
        for subdomain in subdomains:
            response += f"{subdomain.subdomain}\n"
        return response
    else:
        return f"No subdomains found for domain: {domain}", 404
    
@app.route('/api/subdomains/program/<p_name>')
def subdomains_of_program(p_name):
    subdomains = Subdomains.objects(program_name=p_name)
    if subdomains:
        response = ''
        for subdomain in subdomains:
            response += f"{subdomain.subdomain}\n"
        return response
    else:
        return f"No subdomains found for program: {p_name}", 404

#LIVE SUBDOMAIN ROUTES
@app.route('/api/lives/fresh')
def all_lives_fresh():
    twenty_four_hours_ago = datetime.now() - timedelta(hours=24)
    
    fresh_lives = LiveSubdomains.objects(created_date__gte=twenty_four_hours_ago)
    
    res_array = [f"{fresh_live.subdomain}" for fresh_live in fresh_lives]
    return "\n".join(res_array)

@app.route('/api/lives/all')
def all_lives():
    twelve_hours_ago = datetime.now() - timedelta(hours=12)

    lives_obj = LiveSubdomains.objects(last_update__gte=twelve_hours_ago).all()
    
    response = ""
    for live_obj in lives_obj:
        response += f"{live_obj.subdomain}\n"
    
    return response

@app.route('/api/lives/provider/<provider>')
def all_lives_provider(provider):
    subs_obj = Subdomains.objects(providers=[provider])
    twelve_hours_ago = datetime.now() - timedelta(hours=12)

    
    resp = ""
    for sub_obj in subs_obj:
        print(sub_obj.subdomain)  # Debug print (likely for development)
        live = LiveSubdomains.objects(subdomain=sub_obj.subdomain, last_update__gte=twelve_hours_ago).first()
        if live:
            resp += f"{live.subdomain}\n"
    
    return resp

@app.route('/api/lives/program/<p_name>')
def lives_by_program(p_name):
    """
    برگرداندن تمام زیر دامنه‌های زنده متعلق به یک برنامه خاص
    مثال: /api/lives/program/uber
    """
    live_subdomains = LiveSubdomains.objects(program_name=p_name).scalar('subdomain')
    
    if not live_subdomains:
        return f"No live subdomains found for program: {p_name}", 404
    
    return "\n".join(live_subdomains)

@app.route('/api/lives/domain/<path:domain>')
def lives_by_domain(domain):
    clean_domain = normalize_domain(domain)
    
    # جستجو در دیتابیس
    live_subdomains = LiveSubdomains.objects(scope=clean_domain).scalar('subdomain')
    
    if not live_subdomains:
        return f"No live subdomains found for domain: {clean_domain}", 404
    
    return "\n".join(live_subdomains)

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
        "providerss": subdomain_obj.providers if subdomain_obj else [],
        "ips": live_obj.ips or [],
        "cdn": live_obj.cdn,
        "created_date": (
            live_obj.created_date.isoformat()
            if live_obj.created_date
            else None
        ),
        "last_update": (
            live_obj.last_update.isoformat()
            if live_obj.last_update
            else None
        ),
    }

# HTTP RPUTES
@app.route('/api/http/fresh')
def all_http_fresh():
    twenty_four_hours_ago = datetime.now() - timedelta(hours=24)
    
    fresh_https = Http.objects(created_date__gte=twenty_four_hours_ago)
    
    res_array = [f"{fresh_http.url}" for fresh_http in fresh_https]
    return "\n".join(res_array)

@app.route('/api/http/provider/<provider>')
def all_http_provider(provider):
    subs_obj = Subdomains.objects(providers=[provider])
    twelve_hours_ago = datetime.now() - timedelta(hours=12)

    
    resp = ""
    for sub_obj in subs_obj:
        http = Http.objects(subdomain=sub_obj.subdomain, last_update__gte=twelve_hours_ago).first()
        if http:
            resp += f"{http.url}\n"
    
    return resp

@app.route('/api/http/all')
def all_http():
    # twelve_hours_ago = datetime.now() - timedelta(hours=24)

    # http_objs = Http.objects(last_update__gte=twelve_hours_ago).all()
    http_objs = Http.objects().all()
    
    response = ""
    for http_obj in http_objs:
        response += f"{http_obj.url}\n"
    
    return response

if __name__ == '__main__':
    app.run(debug=True)
    
# print(f"Watching directory: {WATCH_DIR}")
