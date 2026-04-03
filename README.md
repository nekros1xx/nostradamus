# Nostradamus

**SQL injection exploitation tool with predictive schema inference engine**

Nostradamus is a fork of [sqlmap](https://github.com/sqlmapproject/sqlmap) enhanced with a multi-layer prediction engine that dramatically reduces the number of queries needed during blind SQL injection data extraction.

## How it works

During blind SQL injection (especially time-based), traditional tools extract data character by character using binary search (~7 queries per character). With `--time-sec=10`, extracting a 15-character table name takes **~17 minutes**.

Nostradamus predicts the full value after extracting just 3-4 characters, then verifies with a single equality query. If correct, it skips the remaining characters entirely.

### Prediction layers (by priority)

| Weight | Layer | Source |
|--------|-------|--------|
| 100 | Schema Learning | Values discovered in current session |
| 80 | Pattern Derived | Detected prefixes + dictionary combos |
| 60 | Common Outputs | Known common outputs |
| 40 | CMS/Framework Tables | 780+ known tables from 17+ products |
| 20 | Language Dictionaries | EN/ES/PT database naming words |

### Supported CMS and Frameworks (780+ known tables)

WordPress (core + WooCommerce + Yoast + plugins), Joomla, Drupal, Magento, PrestaShop, Moodle, Django, Rails, Laravel, Ghost, Strapi, MediaWiki, phpBB, Nextcloud, Discourse, Spring Boot

### Supported products with known SQLi CVEs

SuiteCRM (CVE-2024-36412), vTiger CRM (CVE-2019-11057), Dolibarr ERP (CVE-2018-10094), OrangeHRM, MantisBT, osCommerce, OpenCart, GLPI (CVE-2022-35914), Cacti (CVE-2024-25641), Zabbix

## Installation

### Linux / macOS

```bash
git clone https://github.com/nekros1xx/nostradamus.git && cd nostradamus && chmod +x install.sh && ./install.sh
```

### Windows (PowerShell)

```powershell
git clone https://github.com/nekros1xx/nostradamus.git; cd nostradamus; .\install.bat
```

After installation, restart your terminal. The `nostradamus` command will be available globally from any directory.

### Uninstall

```bash
# Linux / macOS
~/.nostradamus/install.sh --uninstall

# Windows
%USERPROFILE%\.nostradamus\install.bat --uninstall
```

## Usage

100% compatible with sqlmap. All existing flags work identically:

```bash
# Basic usage (predictor activates automatically)
nostradamus -u "http://target.com/page?id=1" --batch --dbs

# Enumerate tables with blind injection
nostradamus -u "http://target.com/page?id=1" --technique=B --batch --tables -D mydb

# Time-based blind (where prediction saves the most time)
nostradamus -u "http://target.com/page?id=1" --technique=T --batch --tables --time-sec=10

# POST injection
nostradamus -u "http://target.com/login" --data="user=admin&pass=test" -p user --batch --dbs

# Disable prediction (for comparison/troubleshooting)
nostradamus -u "http://target.com/page?id=1" --no-predict --batch --dbs
```

## Benchmark results

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

## Efficiency report

At the end of each run, Nostradamus shows prediction statistics with real measured timing:

```
[INFO] predictor stats - hits: 24, misses: 41, hit rate: 37%
[INFO] predictor stats - queries saved: 1141, queries wasted: 41, net: +1100 queries
[INFO] predictor stats - avg query time: 10.34s (measured), time saved: 11802.0s, time wasted: 424.0s
[INFO] predictor verdict: BENEFICIAL (saved 11378.0s = 189.6 min)
```

## Features over sqlmap

- **Predictive schema inference** - multi-layer prediction engine with 34,000+ trie entries
- **780+ CMS/framework table definitions** - instant recognition of known schemas
- **Self-learning** - discovers naming patterns (prefixes, case style, language) as it extracts data
- **Real-time statistics** - measured query timing for accurate savings reports
- **Auto-disable** - stops predicting if the schema is unpredictable (minimizes waste)
- **`--no-predict` flag** - disable prediction for benchmarking

## Credits

Built on top of [sqlmap](https://github.com/sqlmapproject/sqlmap) by the sqlmap developers. The prediction engine and CMS/framework table definitions are original work of [Sergio Cabrera](https://www.linkedin.com/in/sergio-cabrera-878766239/).

## License

Same as sqlmap. See [LICENSE](LICENSE) file.