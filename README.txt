# Watch - Bug Bounty Monitoring & Security Scanner

سیستم خودکار کشف، مانیتورینگ و اسکن امنیتی زیردامنه‌ها برای برنامه‌های Bug Bounty

---

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
- [عیب‌یابی](#عیبیابی)

---

## معرفی

**Watch** یک پلتفرم جامع برای مانیتورینگ خودکار برنامه‌های Bug Bounty است که شامل:

- 🔍 **Enumeration** - کشف زیردامنه‌ها از منابع مختلف
- 🌐 **DNS Resolution** - رزولو و شناسایی زیردامنه‌های زنده
- 🌍 **HTTP Scanning** - اسکن HTTP/HTTPS با httpx
- 🔐 **Vulnerability Scanning** - اسکن آسیب‌پذیری با Nuclei
- 📢 **Notification System** - اطلاع‌رسانی تلگرام
- 🔄 **REST API** - دسترسی به داده‌ها

---

## معماری سیستم

```
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
│watch_nuclei_all │ ← اسکن آسیب‌پذیری
└─────────────────┘
         │
         ▼
    ┌─────────┐
    │ MongoDB │ ← ذخیره‌سازی
    └─────────┘
         │
         ▼
    ┌─────────┐
    │Flask API│ ← دسترسی به داده
    └─────────┘

---

## پیش‌نیازها

### ابزارهای خارجی

bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Nuclei (اختیاری)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# massdns
git clone https://github.com/blechschmidt/massdns.git
cd massdns && make && sudo make install

### نرم‌افزارها

- Python 3.8+
- MongoDB 4.4+
- Docker & Docker Compose (توصیه می‌شود)

---

## نصب و راه‌اندازی

### 1. کلون پروژه

bash
git clone https://github.com/pouyaGit/watch.git
cd watch

### 2. نصب وابستگی‌ها

bash
pip install -r requirements.txt

### 3. تنظیم متغیرهای محیطی

bash
# کپی فایل نمونه
cp .env.example .env

# ویرایش و تنظیم مقادیر
nano .env

**محتویات `.env`:**

bash
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
HTTPX_BIN=/root/go/bin/httpx
WATCH_DIR=/opt/watch

### 4. راه‌اندازی MongoDB

bash
cd database
docker-compose up -d

### 5. اجرایی کردن اسکریپت‌ها

bash
chmod +x watch.sh
chmod +x programs/*.py enum/*.py ns/*.py http/*.py nuclei/*.py

---

## پیکربندی

### تعریف برنامه‌ها

فایل JSON در `programs/` ایجاد کنید:

json
{
  "program_name": "example",
  "scopes": [
    "example.com",
    "*.example.com"
  ],
  "ooscopes": [
    "test.example.com"
  ],
  "config": {
    "telegram_chat_id": "-1001234567890",
    "notify_new_subdomain": true,
    "notify_new_http": true
  }
}

### تنظیمات Nuclei

فایل `nuclei/public-config.yaml`:

yaml
header:
  - 'X-BugBounty-hacker: YourHandle'

concurrency: 25
rate-limit: 100

severity:
  - critical
  - high
  - medium
  - low

exclude-tags:
  - technologies
  - ssl

---

## امکانات

### 🔍 Enumeration

کشف زیردامنه از منابع مختلف:

- **Subfinder** - منابع عمومی و API
- **crt.sh** - Certificate Transparency
- **Wayback Machine** - آرشیو وب
- **AbuseIPDB** - گزارش‌های سوء استفاده

bash
# تک تک
watch_subfinder example.com
watch_crtsh example.com

# همه با هم
watch_enum_all example.com

### 🌐 DNS Resolution

رزولو و شناسایی زیردامنه‌های زنده:

- تشخیص wildcard domains
- شناسایی CDN (Cloudflare, Akamai, etc.)
- DNS brute-force

bash
watch_ns example.com
watch_ns_all

### 🌍 HTTP Scanning

اسکن HTTP/HTTPS با httpx:

- استخراج title, status, headers
- شناسایی تکنولوژی
- **فیلتر خودکار CDN internal**

bash
watch_httpx

### 🔐 Vulnerability Scanning

اسکن با Nuclei templates:

bash
watch_nuclei_all

### 🔄 Automation

اجرای کامل pipeline:

bash
./watch.sh

**زمان‌بندی با Cron:**

bash
# هر 6 ساعت
0 */6 * * * /opt/watch/watch.sh >> /var/log/watch.log 2>&1

---

## API

### راه‌اندازی

bash
python3 app.py

سرور روی `http://0.0.0.0:5000` اجرا می‌شود.

### Endpoints

#### لیست برنامه‌ها

http
GET /programs

#### جزئیات برنامه

http
GET /programs/<program_name>

#### لیست زیردامنه‌ها

http
GET /subdomains?program=<program_name>
GET /subdomains?scope=<domain>

#### زیردامنه‌های زنده

http
GET /live-subdomains?program=<program_name>

**مثال:**

bash
curl "http://localhost:5000/subdomains?program=example"

---

## ساختار پروژه


watch/
├── app.py                    # Flask API
├── config.py                 # تنظیمات
├── watch.sh                  # اسکریپت اصلی
├── requirements.txt
├── .env.example
├── .gitignore
│
├── database/
│   ├── db.py                 # مدل‌های MongoDB
│   ├── notifications.py
│   ├── telegram.py
│   └── docker-compose.yml
│
├── programs/
│   ├── test_program.json     # نمونه
│   └── watch_sync_programs.py
│
├── enum/                     # Enumeration
│   ├── watch_subfinder.py
│   ├── watch_crtsh.py
│   ├── watch_wayback.py
│   ├── watch_abuseipdb.py
│   └── watch_enum_all.py
│
├── ns/                       # DNS Resolution
│   ├── watch_ns.py
│   ├── watch_ns_all.py
│   ├── watch_ns_brute.py
│   └── wildcard_detector.py
│
├── http/                     # HTTP Scanning
│   ├── watch_http.py
│   └── watch_http_all.py
│
├── nuclei/                   # Vulnerability Scanning
│   ├── watch_nuclei_all.py
│   ├── public-config.yaml
│   └── private_templates/
│
└── utils/
    └── common.py

---

## مدل‌های داده

### Programs

python
{
  "program_name": "example",
  "scopes": ["example.com"],
  "ooscopes": ["test.example.com"],
  "config": {...}
}

### Subdomains

python
{
  "subdomain": "api.example.com",
  "scope": "example.com",
  "providers": ["subfinder", "crtsh"]
}

### LiveSubdomains

python
{
  "subdomain": "api.example.com",
  "ips": ["1.2.3.4"],
  "cdn": "cloudflare"  # یا "internal"
}

### Http

python
{
  "subdomain": "api.example.com",
  "url": "https://api.example.com",
  "status_code": 200,
  "title": "API Documentation",
  "tech": ["nginx", "php"]
}

---

## عیب‌یابی

### MongoDB متصل نمی‌شود

bash
docker ps | grep mongo
docker logs mongo
docker-compose restart

### httpx کار نمی‌کند

bash
which httpx
# مسیر را در .env تنظیم کنید

### massdns نصب نیست

bash
git clone https://github.com/blechschmidt/massdns.git
cd massdns && make && sudo make install

---

## نکات امنیتی

⚠️ **هرگز فایل `.env` را commit نکنید**

✅ در production از MongoDB authentication استفاده کنید

✅ برای API از rate limiting استفاده کنید

---

## مشارکت

برای گزارش باگ یا پیشنهاد، Issue ایجاد کنید.

---

## تماس

📧 pouya.gh@outlook.com

---

**⚠️ هشدار:** این پروژه فقط برای استفاده قانونی در برنامه‌های Bug Bounty طراحی شده است.
