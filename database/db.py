from mongoengine import Document, StringField, DateTimeField, ListField, DictField, IntField, connect
from datetime import datetime
import tldextract
import config
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
connect(db='watch', host='mongodb://127.0.0.1:27017/watch')

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
        notify_new_live_subdomain(obj.get('subdomain'), program_name)
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
