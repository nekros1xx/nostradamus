# 🔮 Nostradamus

**SQL injection exploitation tool with predictive schema inference engine**

Nostradamus is a fork of [sqlmap](https://github.com/sqlmapproject/sqlmap) enhanced with a multi-layer prediction engine that dramatically reduces the number of queries needed during blind SQL injection data extraction.

## How it works

During blind SQL injection (especially time-based), traditional tools extract data character by character using binary search (~8 queries per character). With `--time-sec=10`, each character takes ~42 seconds accounting for HTTP latency, SQL engine processing, and the SLEEP delay. A single table name can take 5+ minutes. A full schema can take hours.

Nostradamus predicts the full value after extracting just 3-4 characters, then verifies with a single equality query. If correct, it skips all remaining characters. If wrong, the cost is minimal (~0.3s for a FALSE response).

### Why not sqlmap's --predict-output?

sqlmap includes a built-in `--predict-output` flag (internally called "Good Samaritan"), but it uses a static dictionary of ~1,300 entries, does not learn from the schema being extracted, is incompatible with `--threads` and `-o`, and has no CMS/framework awareness. In practice almost no one uses it.

## Features

### Predictive Schema Inference Engine
- **34,000+ entries** in optimized Trie data structure for O(k) prefix lookup
- **5 prediction layers** with priority weights (learned > CMS detected > pattern > dictionary > language)
- **Self-learning** — detects prefixes, separators, case style (lowercase, UPPERCASE, camelCase, PascalCase), and language (EN/ES/PT) from extracted values
- **Charset hints** — optimizes bisection order even when exact prediction fails (free, no extra queries)
- **Session persistence** — learned patterns survive between runs via hashDB
- **Auto-disable** — stops predicting after 20 attempts with less than 5% hit rate

### Quick Schema Dump
When a CMS is detected and the DBMS is MySQL, Nostradamus verifies all known tables with a single equality query each (`SELECT COUNT(*) FROM information_schema.tables WHERE table_name='candidate'`) instead of extracting character by character. WordPress (35 tables) goes from ~1,400 blind queries to just 35 queries. **97.5% query reduction.** If unknown tables remain, falls back to normal extraction and merges results.

### Pre-Extraction Prediction
Before starting character-by-character bisection, if the value length is known and CMS is detected, Nostradamus tries to verify the full value with one equality query using quick schema candidates filtered by length. If it hits, the entire extraction is skipped.

### Automatic CMS Detection
Identifies the target's CMS/framework automatically from the first discovered fingerprint table and boosts all known tables for that platform to maximum priority. Supported platforms:

WordPress, Joomla, Drupal, Magento, PrestaShop, Moodle, Django, Laravel, Rails, phpBB, Nextcloud, SuiteCRM, vTiger, Dolibarr, GLPI, MantisBT, MediaWiki, Ghost

### Passive HTTP Fingerprinting
Detects the CMS from HTTP response headers, cookies, and body content **before the first table is extracted**. For example, a `wordpress_test_cookie` in cookies or `/wp-content/` in the response body triggers WordPress detection immediately. This maximizes prediction accuracy from the very start of the scan. Supports 13 CMS with header, cookie, and body patterns.

### Column Context Prediction
When extracting column names, Nostradamus knows the expected columns for 40+ common tables across all supported CMS. If it detects you're extracting columns from `wp_users`, it predicts `user_login`, `user_pass`, `user_email`, `display_name`, etc. Works for WordPress, Django, Joomla, Magento, PrestaShop, Moodle, phpBB, vTiger, SuiteCRM, GLPI, MantisBT, Nextcloud, Dolibarr, and generic tables like `users`, `products`, `orders`.

### Value Prediction
When extracting data values, Nostradamus predicts common values based on the column name:

| Column | Predicted values |
|--------|-----------------|
| status | active, inactive, pending, disabled, suspended... |
| post_status | publish, draft, pending, private, trash... |
| role | admin, editor, author, subscriber, moderator... |
| lang / language | en, es, fr, en-US, en-GB, es-ES... |
| payment | credit_card, paypal, bank_transfer... |
| country | United States, Mexico, Brazil, Argentina... |
| active / enabled | 0, 1, yes, no, true, false... |
| type | post, page, user, product, order... |

### Hash Type Prediction
When extracting password hash columns (`password`, `user_pass`, `pass_hash`, etc.), Nostradamus predicts the hash prefix based on the detected CMS:

| CMS | Hash type | Predicted prefix |
|-----|-----------|-----------------|
| WordPress / phpBB | phpass | `$P$B`, `$P$D`, `$H$B` |
| Joomla / GLPI / MantisBT | bcrypt | `$2y$10$`, `$2y$12$` |
| Django | PBKDF2 | `pbkdf2_sha256$`, `argon2$argon2id$` |
| Magento | SHA-256 / bcrypt | `$5$`, `$2y$10$` |
| Laravel | bcrypt | `$2y$10$`, `$2y$12$` |
| Nextcloud | Argon2 / bcrypt | `$argon2id$v=19$`, `$2y$10$` |

Without CMS detection, loads all common hash prefixes: bcrypt, phpass, MD5 crypt, SHA-256, SHA-512, Argon2, MySQL native. A bcrypt hash prefix (`$2y$10$`) saves 7 characters × 8 queries = **56 queries** per hash.

### Email Domain Prediction
When extracting email columns (`email`, `user_email`, `email1`, `contact_email`, etc.), Nostradamus predicts the domain after the `@` is extracted:

`@gmail.com`, `@hotmail.com`, `@yahoo.com`, `@outlook.com`, `@icloud.com`, `@protonmail.com` plus regional variants (`@hotmail.es`, `@gmail.com.br`, `@yahoo.com.ar`, `@yahoo.com.mx`, etc.)

Predicting `@gmail.com` saves 10 characters × 8 queries = **80 queries** per email address.

### CMS-Aware URL/Path Prediction
For URL-type columns (`url`, `avatar`, `image_url`, `filepath`, etc.), loads CMS-specific path prefixes **only when that CMS is detected**:

- **Always loaded**: `http://`, `https://`, `/uploads/`, `/images/`, `/api/`, `/static/`
- **WordPress only**: `/wp-content/uploads/`, `/wp-content/themes/`, `/wp-json/`
- **Moodle only**: `/pluginfile.php/`, `/draftfile.php/`, `/course/`
- **Magento only**: `/media/catalog/product/`, `/pub/static/`
- **Joomla only**: `/components/`, `/administrator/`, `/templates/`
- And more for PrestaShop, Django, Laravel, phpBB, Nextcloud

No cross-CMS false predictions — `/wp-content/` is never suggested for a Moodle target.

### Database Name Prediction
Predicts database names per CMS (e.g., `wordpress`, `bitnami_wordpress`, `wpdb` for WordPress) plus 50+ generic names (`information_schema`, `mysql`, `production`, `ecommerce`, `app`, etc.). CMS-specific names get boosted to maximum priority when CMS is detected.

### Dated/Sharded Pattern Detection
Detects table naming patterns with dates or partition numbers:

- `events_2023_01` → generates `events_2023_02` through `events_2025_12`
- `logs_2023` → generates `logs_2022` through `logs_2027`
- `partition_0` → generates `partition_1` through `partition_19`

### 780+ Known Table Definitions
Pre-loaded schemas for CMS, frameworks, and products with known SQLi CVEs:

| Category | Products | Tables |
|----------|----------|--------|
| CMS | WordPress + WooCommerce + Yoast + plugins, Joomla, Drupal, Ghost, MediaWiki | 180+ |
| E-commerce | Magento, PrestaShop, osCommerce, OpenCart | 145+ |
| Frameworks | Django, Laravel, Rails, Spring Boot, Strapi | 60+ |
| CRM/ERP | SuiteCRM, vTiger, Dolibarr, OrangeHRM | 100+ |
| IT Management | GLPI, MantisBT, Cacti, Zabbix | 90+ |
| Community | phpBB, Nextcloud, Discourse, Moodle | 85+ |

### Real-Time Statistics
At the end of each run, shows CMS detection, hits, misses, measured query timing, and a verdict:

```
[INFO] predictor CMS detected: wordpress
[INFO] predictor stats - hits: 29, misses: 70, hit rate: 29%
[INFO] predictor stats - queries saved: 1491, queries wasted: 70, net: +1421 queries
[INFO] predictor stats - avg query time: 1.51s (measured), time saved: 2235.0s, time wasted: 0.4s
[INFO] predictor verdict: BENEFICIAL (saved 2234.5s = 37.2 min)
```

### Safety Guards
- Max 5 prediction attempts per value
- Only retries when the top candidate changes
- Auto-disables after 20 attempts with less than 5% hit rate
- `--no-predict` flag to disable completely

## Installation

### Linux / macOS

```bash
git clone https://github.com/nekros1xx/nostradamus.git && cd nostradamus && chmod +x install.sh && ./install.sh
```

### Windows (PowerShell)

```powershell
git clone https://github.com/nekros1xx/nostradamus.git; cd nostradamus; .\install.bat
```

After installation, the `nostradamus` command is available globally from any directory.

### Uninstall

```bash
# Linux / macOS
~/.nostradamus/install.sh --uninstall

# Windows
%USERPROFILE%\.nostradamus\install.bat --uninstall
```

## Usage

100% compatible with sqlmap. All existing flags work identically.

### Basic Enumeration

```bash
nostradamus -u "http://target.com/page?id=1" --batch --dbs
nostradamus -u "http://target.com/page?id=1" --batch --tables -D wordpress
nostradamus -u "http://target.com/page?id=1" --batch --columns -D wordpress -T wp_users
nostradamus -u "http://target.com/page?id=1" --batch --dump -D wordpress -T wp_users
```

### Forcing Specific Techniques

```bash
# Boolean-based blind
nostradamus -u "http://target.com/page?id=1" --technique=B --batch --tables

# Time-based blind (where prediction saves the most time)
nostradamus -u "http://target.com/page?id=1" --technique=T --batch --tables --time-sec=10

# Stacked queries
nostradamus -u "http://target.com/page?id=1" --technique=S --batch --tables --time-sec=10
```

### POST and Header Injection

```bash
# POST parameter
nostradamus -u "http://target.com/login" --data="user=admin&pass=test" -p user --batch --dbs

# Cookie injection
nostradamus -u "http://target.com/dashboard" --cookie="session=abc123" -p session --batch --dbs

# Custom header
nostradamus -u "http://target.com/api" --headers="X-Token: 1*" --batch --dbs
```

### MSSQL / Specific DBMS

```bash
nostradamus -u "http://target.com/page" --data="id=5" -p id \
  --dbms="Microsoft SQL Server" --technique=S --batch --tables \
  --time-sec=10 --force-ssl --random-agent
```

### Prediction Control

```bash
# Disable prediction
nostradamus -u "http://target.com/page?id=1" --no-predict --batch --dbs

# Verbose mode (see hits/misses in real-time)
nostradamus -u "http://target.com/page?id=1" --batch --tables -v 3

# Benchmark: compare with and without prediction
time nostradamus -u "http://target.com/?id=1" --technique=B --batch --tables --flush-session
time nostradamus -u "http://target.com/?id=1" --technique=B --batch --tables --flush-session --no-predict
```

### Advanced Options

```bash
# Through Burp Suite proxy
nostradamus -u "http://target.com/page?id=1" --proxy="http://127.0.0.1:8080" --batch --dbs

# WAF bypass with tamper scripts
nostradamus -u "http://target.com/page?id=1" --tamper=space2comment,between --batch --dbs

# Through TOR
nostradamus -u "http://target.com/page?id=1" --tor --tor-type=SOCKS5 --batch --dbs
```

## Benchmark Results

Tested against 26 databases with diverse naming patterns (boolean-based blind):

| Database | Pattern | Hit Rate | Net Queries Saved |
|----------|---------|----------|-------------------|
| WordPress Full | wp_ + plugins | 29% | +1,421 |
| Moodle | mdl_ | 38% | +1,290 |
| MantisBT | mantis_*_table | 41% | +1,255 |
| Magento | catalog/sales/eav | 37% | +1,196 |
| Drupal | cache/node/taxonomy | 41% | +1,165 |
| vTiger CRM | vtiger_ | 37% | +1,100 |
| Joomla | jos_ | 32% | +1,029 |
| GLPI | glpi_ | 39% | +1,020 |
| PrestaShop | ps_ | 37% | +926 |
| Django | auth_/django_ | 43% | +890 |
| SuiteCRM | accounts/contacts | 40% | +889 |
| Dolibarr | llx_ | 36% | +574 |
| phpBB | phpbb_ | 44% | +573 |
| Rails | active_storage | 29% | +529 |
| Nextcloud | oc_ | 33% | +516 |
| Hungarian | tbl* | 22% | +206 |

**Time-based blind (--time-sec=5) with WordPress Full: saved 2,234.5 seconds = 37.2 minutes in a single scan.**

With `--time-sec=10`, each saved query = 10 seconds. For MantisBT (+1,255 queries): **~3.5 hours saved**.

## Credits

Built on top of [sqlmap](https://github.com/sqlmapproject/sqlmap). Developed by [Sergio Cabrera](https://www.linkedin.com/in/sergio-cabrera-878766239/).

## License

Same as sqlmap. See [LICENSE](LICENSE) file.
