# Watch - سیستم مانیتورینگ و اسکن امنیتی Bug Bounty

سیستم خودکار کشف، مانیتورینگ و اسکن امنیتی زیردامنه‌ها برای برنامه‌های Bug Bounty.

## 📋 فهرست مطالب

- [معرفی](#معرفی)
- [معماری سیستم](#معماری-سیستم)
- [پیش‌نیازها](#پیشنیازها)
- [نصب و راه‌اندازی](#نصب-و-راهاندازی)
- [پیکربندی](#پیکربندی)
- [امکانات](#امکانات)
- [نحوه استفاده](#نحوه-استفاده)
- [API](#api)
- [ساختار پروژه](#ساختار-پروژه)

---

## معرفی

**Watch** یک پلتفرم جامع برای مانیتورینگ خودکار برنامه‌های Bug Bounty است که شامل موارد زیر می‌شود:

- **Enumeration**: کشف زیردامنه‌ها از منابع مختلف (Subfinder, crt.sh, Wayback Machine, AbuseIPDB)
- **DNS Resolution**: رزولو کردن و شناسایی زیردامنه‌های زنده با قابلیت brute-force
- **HTTP Scanning**: اسکن HTTP/HTTPS با httpx و استخراج اطلاعات (title, status, headers, favicon)
- **Vulnerability Scanning**: اسکن آسیب‌پذیری با Nuclei
- **Notification System**: اطلاع‌رسانی از طریق Telegram
- **REST API**: دسترسی به داده‌ها از طریق Flask API

---

## معماری سیستم

┌─────────────────┐
│  Programs JSON  │ ← تعریف برنامه‌ها و scope
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ watch_sync_     │ ← همگام‌سازی با MongoDB
│   programs      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ watch_enum_all  │ ← کشف زیردامنه‌ها
│  (subfinder,    │   (Subfinder, crt.sh,
│   crtsh, etc)   │    Wayback, AbuseIPDB)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ watch_ns_all    │ ← رزولو DNS + wildcard detection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ watch_http_all  │ ← اسکن HTTP با httpx
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│watch_nuclei_all │ ← اسکن آسیب‌پذیری (اختیاری)
└─────────────────┘
         │
         ▼
    ┌─────────┐
    │ MongoDB │ ← ذخیره‌سازی داده
    └─────────┘
         │
         ▼
    ┌─────────┐
    │Flask API│ ← دسترسی به داده‌ها
    └─────────┘


---

## پیش‌نیازها

### ابزارهای خارجی

```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Nuclei (اختیاری)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# massdns (برای DNS brute-force)
git clone https://github.com/blechschmidt/massdns.git
cd massdns && make
sudo make install
```

### نرم‌افزارها

- Python 3.8+
- MongoDB 4.4+
- Docker & Docker Compose (توصیه می‌شود)

---

## نصب و راه‌اندازی

### 1. کلون کردن پروژه

```bash
git clone <repository-url>
cd watch
```

### 2. نصب وابستگی‌های Python

```bash
pip install -r requirements.txt
```

**محتویات `requirements.txt`:**
flask
mongoengine
python-telegram-bot
tldextract
psycopg2-binary


### 3. راه‌اندازی MongoDB

#### با Docker Compose (توصیه می‌شود):

```bash
docker-compose up -d
```

این دستور MongoDB را روی `127.0.0.1:27017` اجرا می‌کند و داده‌ها در volume به نام `watchtower-data` ذخیره می‌شوند.

#### نصب مستقیم:

```bash
# Ubuntu/Debian
sudo apt-get install mongodb

# macOS
brew install mongodb-community
```

### 4. اجرایی کردن اسکریپت‌ها

```bash
chmod +x watch.sh
chmod +x programs/*.py
chmod +x enum/*.py
chmod +x ns/*.py
chmod +x http/*.py
chmod +x nuclei/*.py
```

### 5. تنظیم Aliases (اختیاری)

محتویات `README.txt` را به `~/.bashrc` یا `~/.zshrc` اضافه کنید:

```bash
alias watch_sync_programs='python3 /opt/watch/programs/watch_sync_programs.py'
alias watch_subfinder='python3 /opt/watch/enum/watch_subfinder.py'
alias watch_crtsh='python3 /opt/watch/enum/watch_crtsh.py'
alias watch_abuseipdb='python3 /opt/watch/enum/watch_abuseipdb.py'
alias watch_wayback='python3 /opt/watch/enum/watch_wayback.py'
alias watch_enum_all='python3 /opt/watch/enum/watch_enum_all.py'
alias watch_ns='python3 /opt/watch/ns/watch_ns.py'
alias watch_ns_all='python3 /opt/watch/ns/watch_ns_all.py'
alias watch_httpx='python3 /opt/watch/http/watch_http_all.py'
alias watch_nuclei_all='python3 /opt/watch/nuclei/watch_nuclei_all.py'
```

**توجه:** مسیر `/opt/watch/` را با مسیر واقعی پروژه خود جایگزین کنید.

---

## پیکربندی

### 1. تنظیمات اصلی (`config.py`)

```python
WATCH_DIR = "/opt/watch"
TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"  # توکن ربات تلگرام
HTTPX_BIN = "/root/go/bin/httpx"            # مسیر باینری httpx
```

### 2. تعریف برنامه‌ها

فایل‌های JSON در دایرکتوری `programs/` ایجاد کنید:

**مثال: `programs/example.json`**

```json
{
  "program_name": "example",
  "scopes": [
    "example.com",
    "*.example.com"
  ],
  "ooscopes": [
    "test.example.com",
    "dev.example.com"
  ],
  "config": {
    "telegram_chat_id": "-1001234567890",
    "notify_new_subdomain": true,
    "notify_new_http": true
  }
}
```

**فیلدها:**
- `program_name`: نام یکتای برنامه
- `scopes`: لیست دامنه‌های در محدوده
- `ooscopes`: لیست دامنه‌های خارج از محدوده (Out of Scope)
- `config.telegram_chat_id`: شناسه چت تلگرام برای اطلاع‌رسانی
- `config.notify_new_subdomain`: فعال‌سازی نوتیفیکیشن زیردامنه جدید
- `config.notify_new_http`: فعال‌سازی نوتیفیکیشن HTTP جدید

### 3. تنظیمات Nuclei (`nuclei/public-config.yaml`)

```yaml
# HTTP Headers
header:
  - 'X-BugBounty-hacker: Hackerone'
  - 'User-Agent: Mozilla/5.0 ...'

# Performance
concurrency: 25
rate-limit: 100

# Template filtering
exclude-tags:
  - technologies
  - tech
  - ssl
  - dns

severity:
  - critical
  - high
  - medium
  - low

# Exclude specific templates
exclude-templates:
  - wordpress/wordpress-user-enumeration.yaml
  - gitlab/gitlab-public-repos.yaml
  # ... (لیست کامل در فایل)
```

### 4. فایل Resolvers (`resolvers.txt`)

لیست DNS resolverها برای massdns:

8.8.8.8
1.1.1.1
9.9.9.9
208.67.222.222


## امکانات

### 🔍 Enumeration (کشف زیردامنه)

#### 1. Subfinder
- استفاده از منابع عمومی (Certificate Transparency, DNS databases)
- پشتیبانی از API keyها برای منابع پریمیوم

#### 2. crt.sh
- جستجوی Certificate Transparency logs
- کشف زیردامنه‌های صادر شده با SSL

#### 3. Wayback Machine
- استخراج زیردامنه‌ها از آرشیو وب
- کشف زیردامنه‌های قدیمی و حذف شده

#### 4. AbuseIPDB
- کشف زیردامنه‌ها از گزارش‌های سوء استفاده

#### 5. Enum All
- اجرای همزمان تمام ماژول‌های enumeration
- ادغام نتایج و حذف تکراری

**استفاده:**

```bash
watch_sync_programs
# تک تک
watch_subfinder example.com
watch_crtsh example.com
watch_wayback example.com
watch_abuseipdb example.com

# همه با هم
watch_enum_all example.com
```

---

### 🌐 DNS Resolution

#### 1. Basic Resolution (`watch_ns.py`)
- رزولو کردن زیردامنه‌ها با massdns
- شناسایی IP addresses
- تشخیص CDN (Cloudflare, Akamai, etc.)
- **فیلتر کردن wildcard domains**

#### 2. DNS Brute-force (`watch_ns_brute.py`)
- Brute-force با wordlist
- کشف زیردامنه‌های پنهان

#### 3. NS All (`watch_ns_all.py`)
- اجرای resolution برای تمام برنامه‌ها
- پردازش batch

**ویژگی Wildcard Detection:**
- تست با زیردامنه‌های تصادفی
- شناسایی الگوهای wildcard
- جلوگیری از false positive

**استفاده:**

```bash
# رزولو تک دامنه
watch_ns example.com

# رزولو همه برنامه‌ها
watch_ns_all

# DNS brute-force
watch_ns_brute example.com
```

---

### 🌍 HTTP Scanning

#### ویژگی‌ها:
- اسکن HTTP/HTTPS با httpx
- استخراج اطلاعات:
  - Title صفحه
  - Status code
  - Headers
  - Final URL (بعد از redirect)
  - Favicon hash
  - IP addresses
- **فیلتر خودکار CDN internal** (زیردامنه‌هایی با `cdn="internal"` اسکن نمی‌شوند)

**استفاده:**

```bash
# اسکن تک دامنه
python3 http/watch_http.py example.com

# اسکن همه برنامه‌ها
watch_httpx
# یا
python3 http/watch_http_all.py
```

---

### 🔐 Vulnerability Scanning (Nuclei)

#### ویژگی‌ها:
- اسکن با Nuclei templates
- فیلتر severity (critical, high, medium, low)
- Exclude templates خاص
- Custom templates در `nuclei/private_templates/`

**استفاده:**

```bash
watch_nuclei_all
```

**توجه:** در حال حاضر در `watch.sh` غیرفعال است (commented out).

---

### 📢 Notification System

#### Telegram Integration:
- اطلاع‌رسانی زیردامنه جدید
- اطلاع‌رسانی HTTP endpoint جدید
- اطلاع‌رسانی آسیب‌پذیری (Nuclei)

**پیکربندی:**
1. ربات تلگرام بسازید (@BotFather)
2. توکن را در `config.py` قرار دهید
3. Chat ID را در فایل JSON برنامه تنظیم کنید

---

### 🔄 Automation

#### اسکریپت اصلی (`watch.sh`)

```bash
#!/bin/bash

# همگام‌سازی برنامه‌ها
python3 programs/watch_sync_programs.py

# کشف زیردامنه‌ها
python3 enum/watch_enum_all.py

# رزولو DNS
python3 ns/watch_ns_all.py

# اسکن HTTP
python3 http/watch_http_all.py

# اسکن Nuclei (غیرفعال)
# python3 nuclei/watch_nuclei_all.py
```

**اجرا:**

```bash
./watch.sh
```

**زمان‌بندی با Cron:**

```bash
# هر 6 ساعت یکبار
0 */6 * * * /path/to/watch/watch.sh >> /var/log/watch.log 2>&1

# هر روز ساعت 2 صبح
0 2 * * * /path/to/watch/watch.sh >> /var/log/watch.log 2>&1
```

---

## API

### راه‌اندازی Flask API

```bash
python3 app.py
```

سرور روی `http://0.0.0.0:5000` اجرا می‌شود.

### Endpoints

#### 1. لیست برنامه‌ها

```http
GET /programs
```

**پاسخ:**
```json
[
  {
    "program_name": "example",
    "scopes": ["example.com"],
    "ooscopes": ["test.example.com"],
    "config": {...},
    "created_date": "2025-05-11T10:00:00"
  }
]
```

#### 2. جزئیات یک برنامه

```http
GET /programs/<program_name>
```

#### 3. لیست زیردامنه‌ها

```http
GET /subdomains?program=<program_name>
GET /subdomains?scope=<domain>
GET /subdomains?subdomain=<subdomain>
```

**مثال:**
```bash
curl "http://localhost:5000/subdomains?program=example"
```

#### 4. لیست زیردامنه‌های زنده

```http
GET /live-subdomains?program=<program_name>
GET /live-subdomains?scope=<domain>
GET /live-subdomains?subdomain=<subdomain>
```

**پاسخ:**
```json
[
  {
    "subdomain": "api.example.com",
    "scope": "example.com",
    "ips": ["1.2.3.4"],
    "cdn": "cloudflare",
    "created_date": "2025-05-11T10:00:00"
  }
]
```

---

## ساختار پروژه

watch/
├── app.py                    # Flask API
├── config.py                 # تنظیمات اصلی
├── watch.sh                  # اسکریپت اجرای اصلی
├── requirements.txt          # وابستگی‌های Python
├── README.txt                # Aliases و دستورات
├── domains.txt               # Wordlist برای brute-force
├── resolvers.txt             # DNS resolvers
├── resume.cfg                # فایل resume (خودکار)
│
├── database/                 # لایه دیتابیس
│   ├── db.py                 # مدل‌های MongoDB
│   ├── notifications.py      # سیستم نوتیفیکیشن
│   ├── telegram.py           # Telegram bot
│   └── docker-compose.yml    # MongoDB container
│
├── programs/                 # مدیریت برنامه‌ها
│   ├── *.json                # فایل‌های تعریف برنامه
│   └── watch_sync_programs.py
│
├── enum/                     # ماژول‌های Enumeration
│   ├── watch_subfinder.py
│   ├── watch_crtsh.py
│   ├── watch_wayback.py
│   ├── watch_abuseipdb.py
│   └── watch_enum_all.py
│
├── ns/                       # ماژول‌های DNS
│   ├── watch_ns.py
│   ├── watch_ns_all.py
│   ├── watch_ns_brute.py
│   └── wildcard_detector.py
│
├── http/                     # ماژول‌های HTTP
│   ├── watch_http.py
│   └── watch_http_all.py
│
├── nuclei/                   # ماژول‌های Nuclei
│   ├── watch_nuclei_all.py
│   ├── public-config.yaml    # تنظیمات Nuclei
│   └── private_templates/    # Custom templates
│       └── xss.yaml
│
└── utils/                    # توابع کمکی
    └── common.py


---

## مدل‌های داده (MongoDB)

### 1. Programs

```python
{
  "program_name": "example",
  "scopes": ["example.com"],
  "ooscopes": ["test.example.com"],
  "config": {...},
  "created_date": datetime
}
```

### 2. Subdomains

```python
{
  "program_name": "example",
  "subdomain": "api.example.com",
  "scope": "example.com",
  "providers": ["subfinder", "crtsh"],
  "created_date": datetime,
  "last_update": datetime
}
```

### 3. LiveSubdomains

```python
{
  "program_name": "example",
  "subdomain": "api.example.com",
  "scope": "example.com",
  "ips": ["1.2.3.4"],
  "cdn": "cloudflare",  # یا "internal" یا null
  "created_date": datetime,
  "last_update": datetime
}
```

### 4. Http

```python
{
  "program_name": "example",
  "subdomain": "api.example.com",
  "scope": "example.com",
  "ips": ["1.2.3.4"],
  "tech": ["nginx", "php"],
  "title": "API Documentation",
  "status_code": 200,
  "headers": {...},
  "url": "https://api.example.com",
  "final_url": "https://api.example.com/v1",
  "favicon": "hash...",
  "created_date": datetime,
  "last_update": datetime
}
```

---

## نکات امنیتی

1. **توکن تلگرام:** هرگز `config.py` را commit نکنید. از environment variable استفاده کنید:

```python
import os
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', 'default_token')
```

2. **MongoDB:** در production از authentication استفاده کنید:

```yaml
# docker-compose.yml
environment:
  MONGO_INITDB_ROOT_USERNAME: admin
  MONGO_INITDB_ROOT_PASSWORD: secure_password
```

3. **API:** در production از authentication و rate limiting استفاده کنید.

---

## عیب‌یابی

### MongoDB متصل نمی‌شود

```bash
# بررسی وضعیت
docker ps | grep mongo

# لاگ‌ها
docker logs mongo

# ریستارت
docker-compose restart
```

### httpx کار نمی‌کند

```bash
# بررسی نصب
which httpx

# آپدیت مسیر در config.py
HTTPX_BIN = "/path/to/httpx"
```

### massdns نصب نیست

```bash
# نصب
git clone https://github.com/blechschmidt/massdns.git
cd massdns && make && sudo make install
```

---

## مشارکت

برای گزارش باگ یا پیشنهاد ویژگی جدید، Issue ایجاد کنید.

---

## تماس

pouya.gh@outlook.com

---

**نکته:** این پروژه برای استفاده شخصی و برنامه‌های Bug Bounty قانونی طراحی شده است. از آن برای اسکن غیرمجاز استفاده نکنید.