from mongoengine import Document, StringField, BooleanField, DateTimeField, ListField, DictField, IntField, connect
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import tldextract
import config
import re
from database.notifications import (
    notify_new_live_subdomain,
    notify_updated_live_subdomain_ip,
    notify_updated_live_subdomain_cdn,
    notify_title_change,
    notify_status_change,
    notify_new_http
)

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_domain_name(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

# Connect to MongoDB
# connect(db='watch', host='mongodb://127.0.0.1:27017/watch')
connect(
    db='watch',
    host='mongodb://pouya:YourStrongPassword123@127.0.0.1:27017/watch?authSource=admin'
)

# Define the Programs model
class Programs(Document):
    program_name = StringField(required=True)
    created_date = DateTimeField(default=datetime.now())
    config = DictField()
    scopes = ListField(StringField(), default=[])
    ooscopes = ListField(StringField(), default=[])
    
    meta = {
        'indexes': [
            {'fields': ['program_name'], 'unique': True}  # Create a unique index on 'name'
        ]
    }

# Define the Subdomains model
class Subdomains(Document):
    program_name = StringField(required=True)
    subdomain = StringField(required=True)
    scope = StringField(required=True)
    providers = ListField(StringField())
    created_date = DateTimeField(default=datetime.now())
    last_update = DateTimeField(default=datetime.now())

    meta = {
        'indexes': [
            {'fields': ['program_name', 'subdomain'], 'unique': True}  # Create a unique index on program_name and subdomain
        ]
    }

class Http(Document):
    program_name = StringField(required=True)
    subdomain    = StringField(required=True)
    scope        = StringField(required=True)
    ips          = ListField(StringField())
    tech         = ListField(StringField())
    title        = StringField()
    status_code  = IntField()
    headers      = DictField()
    url          = StringField()
    final_url    = StringField()
    favicon    = StringField()
    created_date = DateTimeField(default=datetime.now())
    last_update  = DateTimeField(default=datetime.now())

    meta = {
        'indexes': [
            {'fields': ['program_name', 'subdomain'], 'unique': True}
        ]
    }

class LiveSubdomains(Document):
    program_name = StringField(required=True)
    subdomain = StringField(required=True)
    scope = StringField(required=True)
    ips = ListField(StringField())
    cdn = StringField()
    created_date = DateTimeField(default=datetime.now())
    last_update = DateTimeField(default=datetime.now())

    meta = {
        'indexes': [
            {'fields': ['program_name', 'subdomain'], 'unique': True}  # Create a unique index on program_name + subdomain
        ]
    }

# --- مدل جدید: نتایج کرال ---
class Urls(Document):
    program_name = StringField(required=True)
    subdomain    = StringField(required=True)
    url          = StringField(required=True)
    path         = StringField()
    params       = ListField(StringField())
    sources      = ListField(StringField())      # ["katana", "wayback-robots", ...]
    status_code  = IntField()
    created_date = DateTimeField(default=datetime.now())
    last_update  = DateTimeField(default=datetime.now())
 
    meta = {
        'indexes': [
            {'fields': ['program_name', 'url'], 'unique': True}
        ]
    }

# --- مدل جدید: اندپوینت یکتا (سطح path، نه URL کامل) ---
class Endpoints(Document):
    program_name       = StringField(required=True)
    subdomain          = StringField(required=True)
    path               = StringField(required=True)
    example_url        = StringField()             # یه URL نمونه، برای اجرای x8 روش
    params             = ListField(StringField())          # مجموع همه‌ی پارامترها (کرال + x8)
    params_from_crawl  = ListField(StringField())
    params_from_x8     = ListField(StringField())
    x8_checked         = BooleanField(default=False)
    x8_last_checked    = DateTimeField()
    hit_count          = IntField(default=1)       # چندبار این path تو کرال دیده شده
    created_date       = DateTimeField(default=datetime.now())
    last_update        = DateTimeField(default=datetime.now())
 
    meta = {
        'indexes': [
            {'fields': ['program_name', 'subdomain', 'path'], 'unique': True},
            {'fields': ['x8_checked']},
            {'fields': ['-hit_count']},
        ]
    }
 


# Upsert Programs
def upsert_program(program_name, scopes, ooscopes, config):
    program = Programs.objects(program_name=program_name).first()
    
    if program:
        # Update existing program fields
        program.scopes = scopes
        program.ooscopes = ooscopes
        program.config = config
        program.save()
        print(f"[{current_time()}] Synced program: {program.program_name}")
    else:
        # Create new program
        new_program = Programs(
            program_name=program_name,
            created_date=datetime.now(),
            scopes=scopes,
            ooscopes=ooscopes,
            config=config,
        )
        new_program.save()
        print(f"[{current_time()}] Inserted new program: {new_program.program_name}")

# Check if subdomain exists, if not insert, if yes update providers
def upsert_subdomain(program_name, subdomain_name, provider):
    program = Programs.objects(program_name=program_name).first()
    if get_domain_name(subdomain_name) not in program.scopes or subdomain_name in program.ooscopes:
        print(f"[{current_time()}] subdomain is not in scope: {subdomain_name}")
        return True
        
    existing = Subdomains.objects(program_name=program_name, subdomain=subdomain_name).first()
    if existing:
        if provider not in existing.providers:
            existing.providers.append(provider)
            existing.last_update = datetime.now()
            existing.save()
            print(f"[{current_time()}] Updated subdomain: {subdomain_name}")
        else:
            print(f"[{current_time()}] No update needed for subdomain: {subdomain_name}")
    else:
        new_subdomain = Subdomains(
            program_name=program_name,
            subdomain=subdomain_name,
            scope=get_domain_name(subdomain_name),
            providers=[provider],
            created_date=datetime.now(),
            last_update=datetime.now()
        )
        new_subdomain.save()
        print(f"[{current_time()}] Inserted new subdomain: {subdomain_name}")

def upsert_lives(obj):
    # Resolve program safely
    program = Programs.objects(scopes=obj.get('domain')).first()
    program_name = program.program_name if program else "Unknown"

    # Normalize input IPs
    new_ips = obj.get('ips') or []
    if not isinstance(new_ips, list):
        new_ips = [new_ips] if new_ips else []
    new_ips = [ip for ip in new_ips if ip]
    new_ips_sorted = sorted(new_ips)

    # Normalize CDN value
    allowed_cdns = {"Internal", "Cloudflare", "Cloudfront", "Fastly", "Akamai", "Normal"}
    new_cdn = (obj.get('cdn') or "").strip()
    if not new_cdn or new_cdn not in allowed_cdns:
        new_cdn = "Normal"

    existing = LiveSubdomains.objects(subdomain=obj.get('subdomain')).first()

    if existing:
        old_ips_sorted = sorted(existing.ips or [])
        old_cdn = (getattr(existing, "cdn", None) or "").strip() or "Normal"

        changed_ip = False
        changed_cdn = False
        # Update IPs if changed
        if new_ips_sorted != old_ips_sorted:
            existing.ips = new_ips_sorted
            changed_ip = True

        # Update CDN if changed
        if old_cdn != new_cdn:
            existing.cdn = new_cdn
            changed_cdn = True

        existing.last_update = datetime.now()
        existing.save()

        if changed_ip:
            notify_updated_live_subdomain_ip(obj.get('subdomain'), program_name)
            print(f"[{current_time()}] Updated Live subdomain: {obj.get('subdomain')} (ips changed)")
        if changed_cdn:
            notify_updated_live_subdomain_cdn(obj.get('subdomain'), program_name, new_cdn)
            print(f"[{current_time()}] Updated Live subdomain: {obj.get('subdomain')} (cdn changed)")
        else:
            print(f"[{current_time()}] Live subdomain unchanged: {obj.get('subdomain')}")

    else:
        new_live_subdomain = LiveSubdomains(
            program_name=program_name,
            subdomain=obj.get('subdomain'),
            scope=obj.get('domain'),
            ips=new_ips_sorted,
            cdn=new_cdn,
            created_date=datetime.now(),
            last_update=datetime.now()
        )
        new_live_subdomain.save()
        # notify_new_live_subdomain(obj.get('subdomain'), program_name)
        print(f"[{current_time()}] Inserted new live subdomain: {obj.get('subdomain')}")

    return True


def upsert_http(obj):
    program = Programs.objects(scopes=obj.get('scope')).first()
    # program.program_name

    existing = Http.objects(subdomain=obj.get('subdomain')).first()
    if existing:
        if obj.get('title') != existing.title:
            notify_title_change(obj.get('subdomain'), existing.title, obj.get('title'))
            print(f"[{current_time()}] Title changed for {obj.get('subdomain')}: {existing.title} -> {obj.get('title')}")
            existing.title = obj.get('title')

        if obj.get('status_code') != existing.status_code:
            notify_status_change(obj.get('subdomain'), existing.status_code, obj.get('status_code'))
            print(f"[{current_time()}] Status code changed for {obj.get('subdomain')}: {existing.status_code} -> {obj.get('status_code')}")
            existing.status_code = obj.get('status_code')

        existing.ips = obj.get('ips')
        existing.tech = obj.get('tech')
        existing.headers = obj.get('headers')
        existing.url = obj.get('url')
        existing.final_url = obj.get('final_url')
        existing.favicon = obj.get('favicon')
        existing.last_update = datetime.now()
        existing.save()
    else:
        new_http = Http(
            program_name = program.program_name,
            subdomain    = obj.get('subdomain'),
            scope        = obj.get('scope'),
            ips          = obj.get('ips'),
            tech         = obj.get('tech'),
            title        = obj.get('title'),
            status_code  = obj.get('status_code'),
            headers      = obj.get('headers'),
            url          = obj.get('url'),
            final_url    = obj.get('final_url'),
            favicon      = obj.get('favicon'),
            created_date = datetime.now(),
            last_update  = datetime.now()
        )
        new_http.save()
        notify_new_http(obj.get('subdomain'), program.program_name)
        print(f"[{current_time()}] Inserted new http: {obj.get('subdomain')}")
    
    return True

def delete_program_and_related(program_name: str):
    # حذف تمام داده‌های وابسته
    sub_count = Subdomains.objects(program_name=program_name).delete()
    live_count = LiveSubdomains.objects(program_name=program_name).delete()
    http_count = Http.objects(program_name=program_name).delete()

    prog_count = Programs.objects(program_name=program_name).delete()

    print(
        f"[{current_time()}] Deleted program '{program_name}' | "
        f"Programs: {prog_count}, Subdomains: {sub_count}, "
        f"LiveSubdomains: {live_count}, Http: {http_count}"
    )

# --- جایگزین upsert_url قبلی کن (خط upsert_endpoint اضافه شده وسطش) ---
def upsert_url(program_name, subdomain, url, source):
    """
    ثبت یا آپدیت یک URL کشف‌شده از کرال، با استخراج خودکار پارامترهای query.
    هم‌زمان کالکشن Endpoints (سطح path، بدون انفجار حجم) رو هم آپدیت می‌کنه.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False
 
    path = parsed.path or "/"
    params = sorted(set(parse_qs(parsed.query).keys()))
 
    # --- سطح endpoint (dedup شده بر اساس path، نه URL کامل) ---
    try:
        upsert_endpoint(program_name, subdomain, path, url, params)
    except Exception:
        pass
 
    existing = Urls.objects(program_name=program_name, url=url).first()
    if existing:
        changed = False
        if source not in (existing.sources or []):
            existing.sources = (existing.sources or []) + [source]
            changed = True
        new_params = set(params) - set(existing.params or [])
        if new_params:
            existing.params = sorted(set((existing.params or []) + params))
            changed = True
        if changed:
            existing.last_update = datetime.now()
            existing.save()
        return False
 
    Urls(
        program_name=program_name,
        subdomain=subdomain,
        url=url,
        path=path,
        params=params,
        sources=[source],
        created_date=datetime.now(),
        last_update=datetime.now()
    ).save()
    return True
 

_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_NUM_RE  = re.compile(r'^\d+$')
_HEX_RE  = re.compile(r'^[0-9a-fA-F]{16,}$')   # هش‌های طولانی (session id, hash, ...)


def normalize_path(path):
    """
    segmentهای متغیر (ID عددی، UUID، هش) رو با placeholder جایگزین می‌کنه
    تا /user/12345/profile و /user/67890/profile یه اندپوینت حساب بشن.
    """
    if not path:
        return "/"
    parts = path.split("/")
    normalized = []
    for seg in parts:
        if not seg:
            normalized.append(seg)
        elif _UUID_RE.match(seg):
            normalized.append("{uuid}")
        elif _NUM_RE.match(seg):
            normalized.append("{id}")
        elif _HEX_RE.match(seg):
            normalized.append("{hash}")
        else:
            normalized.append(seg)
    return "/".join(normalized)


# --- تغییر داخل upsert_endpoint: خط اول تابع رو اضافه کن ---
def upsert_endpoint(program_name, subdomain, path, url, params):
    path = normalize_path(path)   # <-- این خط رو اضافه کن، قبل از هر چیز دیگه

    existing = Endpoints.objects(program_name=program_name, subdomain=subdomain, path=path).first()
    if existing:
        changed = False
        if url and not existing.example_url:
            existing.example_url = url
        new_params = set(params) - set(existing.params_from_crawl or [])
        if new_params:
            existing.params_from_crawl = sorted(set((existing.params_from_crawl or []) + params))
            existing.params = sorted(set((existing.params or []) + params))
            changed = True
        existing.hit_count = (existing.hit_count or 0) + 1
        if changed:
            existing.last_update = datetime.now()
        existing.save()
        return False

    Endpoints(
        program_name=program_name,
        subdomain=subdomain,
        path=path,
        example_url=url,
        params=params,
        params_from_crawl=params,
        hit_count=1,
    ).save()
    return True



# =========================DnsBrute===================================
# extends DnsBruteStatus with static/dynamic run tracking
# ==========================DnsBrute==================================

class DnsBruteStatus(Document):
    program_name      = StringField(required=True)
    domain            = StringField(required=True, unique=True)
    feasible          = BooleanField()          # None = never checked yet
    wildcard_ips      = ListField(StringField())
    last_checked      = DateTimeField()         # feasibility precheck
    last_static_run   = DateTimeField()         # watch_dns_static.py
    last_dynamic_run  = DateTimeField()         # watch_dns_dynamic.py

    meta = {
        'indexes': [
            {'fields': ['domain'], 'unique': True}
        ]
    }


def upsert_dns_brute_status(program_name, domain, feasible, wildcard_ips):
    existing = DnsBruteStatus.objects(domain=domain).first()
    if existing:
        existing.feasible = feasible
        existing.wildcard_ips = sorted(wildcard_ips)
        existing.last_checked = datetime.now()
        existing.save()
    else:
        DnsBruteStatus(
            program_name=program_name,
            domain=domain,
            feasible=feasible,
            wildcard_ips=sorted(wildcard_ips),
            last_checked=datetime.now(),
        ).save()


def mark_static_run(domain):
    DnsBruteStatus.objects(domain=domain).update_one(
        set__last_static_run=datetime.now(), upsert=True
    )


def mark_dynamic_run(domain):
    DnsBruteStatus.objects(domain=domain).update_one(
        set__last_dynamic_run=datetime.now(), upsert=True
    )


def get_feasible_domains_ordered(run_field):
    """
    Returns [(program_name, domain), ...] for domains marked feasible=True,
    ordered least-recently-run first for the given run_field
    ('last_static_run' or 'last_dynamic_run'). Never-run domains come first.
    """
    statuses = list(DnsBruteStatus.objects(feasible=True))
    statuses.sort(key=lambda s: getattr(s, run_field) or datetime.min)
    return [(s.program_name, s.domain) for s in statuses]