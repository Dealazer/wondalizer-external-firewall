# Wondalizer External Firewall

**Version:** 8.1.8  
**Requires at least:** WordPress 6.4  
**Tested up to:** WordPress 7.0  
**Requires PHP:** 7.4+  
**License:** GPL-2.0+  

A comprehensive external firewall for WordPress that blocks unwanted HTTP/cURL requests, email interception, cron execution, and detects obfuscated code — all with granular per-plugin and per-theme control.

Donate to PayPal.me/Dealazer or look in the main file for other donation link

---

## 🔥 Features

### HTTP / cURL Firewall
- Block or allow external HTTP requests on a per-plugin and per-theme basis
- Domain whitelist and blacklist with wildcard support (`*.tracker.com`)
- Automatic WordPress core detection — core updates are never blocked
- reCAPTCHA-safe by default — Google domains are whitelisted unless explicitly disabled
- Same-site exception — blocked plugins can still access your own domain (essential for cache plugins)

### Email Firewall
- Block or allow email sending (`wp_mail()`, `mail()`) per extension
- Independent from HTTP controls — block emails without blocking HTTP
- Full logging of blocked and allowed email attempts

### Cron Firewall
- Block all external HTTP requests made during WordPress cron execution (`wp-cron.php`)
- Whitelist specific cron hooks to allow them internet access
- Prevents blocked plugins from bypassing the firewall via scheduled tasks

### cURL Cache Engine (Extension Rewriting)
- **Physically rewrites** plugin and theme PHP files to intercept:
  - `curl_init()`, `curl_setopt()`, `curl_setopt_array()`, `curl_exec()`
  - `fsockopen()`, `pfsockopen()`, `stream_socket_client()`
  - `mail()`, `wp_mail()`
- Rewritten code routes through WordPress filters for firewall enforcement
- Optional auto-rewrite on plugin/theme activation
- One-click restore to original files

### Obfuscation Detection (Bad Potential)
- Detects base64-encoded, hex-encoded, and other obfuscated code patterns
- Assigns threat scores to plugins and themes
- Read-only by default — scan without modifying files
- One-click block all extensions flagged as high risk
- **Wondalizer External Firewall is automatically excluded** from its own Bad Potential list

### Logging & Diagnostics
- Comprehensive logging of all HTTP requests, email attempts, and cron activity
- Color-coded log entries (green = allowed, red = blocked, blue = same-site, purple = email)
- Configurable retention (1–90 days)
- Circuit breaker pattern prevents database overload
- Logger health diagnostics directly in the admin panel

### Dashboard Widget
- Real-time statistics on the WordPress dashboard
- Quick overview of HTTP blocked, email activity, and Bad Potential count

### MU-Plugin Support
- Optional must-use plugin for **early boot protection**
- Intercepts requests before plugins fully load
- Maximum security mode for high-risk environments

---

## 📦 Installation

### Standard Installation

1. Upload the plugin files to `/wp-content/plugins/wondalizer-external-firewall/`
2. Activate the plugin through **Plugins → Installed Plugins** in WordPress
3. Navigate to **External Firewall** in the admin sidebar to configure settings

### MU-Plugin Installation (Optional, Recommended)

For maximum protection, install the MU helper:

1. Go to **External Firewall → Settings**
2. Check **"I UNDERSTAND that enabling Cache Engine will modify files on disk"**
3. Check **"Enable Rewrite Engine Master Switch"**
4. The plugin will automatically install the MU helper to `wp-content/mu-plugins/`

---

## ⚙️ Settings Overview

### Explicit Logging Options
- **Logging Engine** — Master on/off switch for all logging
- **HTTP Logs** — Log blocked and/or allowed HTTP requests
- **Email Logs** — Log blocked and/or allowed emails
- **Internal HTTP** — Log same-site / localhost requests
- **cURL Cache Logs** — Log all intercepted calls from rewritten plugins
- **Log Retention** — Auto-cleanup after N days (default: 14)

### Domain Controls
- **Whitelisted Domains** — Always allowed, one per line
- **Blocked Domains** — Always blocked, supports wildcards
- **Auto-Whitelist WordPress Core** — One-click add all core domains
- **Auto-Whitelist reCAPTCHA** — One-click add Google reCAPTCHA domains

### Same-Site Connection Control
- **Allow Same-Site for Blocked** (default: ON) — Essential for cache plugins (WP Rocket, W3 Total Cache, LiteSpeed Cache) that need to warm caches via same-site requests. When disabled, blocked plugins are blocked from **all** HTTP including your own domain.

### Global Blocking Behaviors
- **Block ALL new plugins** from HTTP by default
- **Block ALL new themes** from HTTP by default
- **Block ALL new plugins** from email by default
- **Block ALL new themes** from email by default

### Commerce Whitelists
- **WooCommerce** — Always allow orders, webhooks, API calls
- **Easy Digital Downloads** — Always allow purchase receipts
- **PayPal** — Always allow IPN, PDT, payment confirmations

### cURL & Mail Rewrite Engine
- **Enable Cache Engine** — Master switch for file rewriting
- **Granular Rewrites** — Enable cURL, Socket, and/or PHP mail() interception separately
- **Auto Rewrite** — Automatically rewrite on plugin/theme activation and updates

---

## 🛡️ How It Works

### HTTP Request Flow

```
Plugin makes HTTP request
        ↓
Firewall intercepts via pre_http_request filter
        ↓
Same-site check → allow if enabled and same domain
        ↓
Whitelist check → allow if domain is whitelisted
        ↓
Blacklist check → block if domain is blacklisted
        ↓
Plugin blocklist check → block if plugin is blocked
        ↓
Default behavior → allow or block based on settings
        ↓
Log entry created (if logging enabled)
```

### Email Flow

```
Plugin calls wp_mail() or mail()
        ↓
Firewall intercepts via pre_wp_mail filter
        ↓
Plugin blocklist check → block if plugin is blocked
        ↓
Default behavior → allow or block based on settings
        ↓
Log entry created (if logging enabled)
```

### Cron Flow

```
WordPress runs wp-cron.php
        ↓
Cron Firewall is active
        ↓
Hook whitelist check → allow if hook is whitelisted
        ↓
Hook blocklist check → block if hook is blocked
        ↓
Default behavior → allow or block based on settings
```

---

## 🎨 Admin Interface

The plugin adds a top-level admin menu **External Firewall** with these tabs:

| Tab | Description |
|-----|-------------|
| **🌐 HTTP Firewall** | Per-plugin and per-theme HTTP blocking controls |
| **✉️ Email Control** | Per-plugin and per-theme email blocking controls |
| **🔧 cURL Cache** | Extension rewriting interface with restore capability |
| **☠️ Bad Potential** | Obfuscation detection results with threat scores |
| **⏰ Cron Firewall** | Scheduled event management with allow/block lists |
| **⚙️ Settings** | All configuration options, logging, domains, whitelists |
| **📄 Logs** | Real-time activity feed with color-coded entries |
| **❤️ About** | System info, donation link, HearThis player |

---

## 🧪 Frequently Asked Questions

### Does this plugin block WordPress core updates?

**No.** The plugin automatically detects WordPress core requests (`api.wordpress.org`, `downloads.wordpress.org`, `planet.wordpress.org`, etc.) and classifies them appropriately. Core functionality is never blocked.

### Will this break my cache plugin?

**No — if Same-Site exception is enabled (default).** Cache plugins like WP Rocket, W3 Total Cache, and LiteSpeed Cache often make same-site HTTP requests to warm caches or generate static files. The Same-Site exception ensures these continue to work even when the plugin is blocked from external requests.

### Will this break my contact forms?

**No — if reCAPTCHA whitelist is enabled (default).** Google reCAPTCHA and gstatic domains are whitelisted by default. You can disable this in Settings if you want to block them explicitly.

### How does the cURL Cache Engine work?

It **physically rewrites** plugin and theme PHP files to replace raw `curl_init()`, `fsockopen()`, `mail()`, etc. with wrapper functions that route through WordPress filters. This allows the firewall to intercept requests even when plugins bypass standard WordPress APIs. Files can be restored to their original state at any time.

### Is the obfuscation detection safe?

**Yes — it is read-only by default.** The scanner reads plugin/theme files and detects patterns like `base64_decode()`, `hex2bin()`, `eval()`, etc. It does not modify any files. You can then choose to block flagged extensions manually.

### Can I export/import settings?

Settings are stored in WordPress options (`won2_firewall_settings`, `won2_blocked_plugins`, etc.) and can be exported/imported via standard WordPress backup plugins or WP-CLI.

---

## ✅ Plugin Check & Compliance Notes

- **No remote file loading — the plugin calls no servers at all.** All CSS/JS is bundled locally in `assets/` and served via `wp_enqueue_*`; the plugin initiates zero outbound requests of its own and needs no account, API key, or connection to the author's servers. The flagged domain strings are local *text data*, never fetched: `data-domains="google.com|gstatic.com|recaptcha.net"` on the reCAPTCHA auto-whitelist button (class-render-settings.php), the same names as a PHP array when saving that preset (class-admin-actions.php), and `placeholder.com`/`placeholder.org` in the scanner's `FALSE_POSITIVE_DOMAINS` ignore-list (class-scan.php).
- **cURL usage is the firewall service itself — nothing is ever sent to us.** `wondalizer-fw-curl-guard.php` is a pass-through shim servicing cURL handles that belong to *other* plugins/themes, rewritten only with the administrator's explicit consent. Every URL is vetted through the WordPress HTTP API's own `pre_http_request` filter before any handle runs. The raw `\curl_exec($ch)` cannot be converted to `wp_remote_*()`: PHP cannot read back the options the originating plugin set on its handle, so reconstruction through the HTTP API would corrupt its requests. `http://won1-blocked.invalid/` is an intentionally unresolvable `.invalid` placeholder used to neutralize blocked handles — never a real call.
- **ABSPATH** is only used to recognize WordPress core files during source tracing.
- **Enqueued assets only:** all admin CSS/JS is served via `wp_enqueue_style()`/`wp_enqueue_script()` with `wp_localize_script()` — no inline `<script>`/`<style>` output.
- **Unique prefixes:** `won1_` (firewall domain data) and `won2_` (functions, classes, options) are used everywhere; legacy `wfw_*`/`wondalizer_*` option names are migrated automatically on first run.

## 🔄 Changelog

### 8.1.8
- **Reviewer compliance documentation:** both readmes now state explicitly that the plugin loads no remote files, calls no servers, and needs no account — the flagged domain strings are local whitelist-preset text data, never fetched
- **cURL shim documented inline:** every raw cURL call site now carries a justification comment — the shim only executes third-party handles whose URLs already passed the HTTP API `pre_http_request` firewall check

### 8.1.7
- **Domains modal exceptions now work on the frontend too:** the guard layer ran before the main firewall and ignored per-plugin (Domains modal) and global allowed-domain exceptions for blocked plugins — all three firewall layers now honor them
- **MU plugins are scannable again:** the roster registers must-use plugins as `mu-<name>` (single files), which the scan engine could not resolve — scanning, the Domains modal and rewrite now work for MU plugins
- Domains saved via the Domains modal are normalized (lowercase, no scheme, no trailing slash, no empty lines); older entries are normalized on read
- Removed a leftover unused render file; readme short description now complies with the 150-character limit

### 8.1.6
- **Core unblock fixed for good:** core was listed under several names across versions (`core`, `wp-core`, `wordpress-core`) — the firewall blocked on any of them but Unblock removed only one. All layers now treat every core alias as one entity and Unblock removes all aliases from every block list
- Core block/unblock now runs through the exact same code path as plugins/themes (special-case branch removed), keeping whitelist/domain/same-site exemptions when blocked
- Roster badge now matches the firewall exactly; form-post block/unblock clears the full object cache

### 8.1.5
- **Unblock now truly unblocks:** the single-row Unblock button only removed the entry from the plugin block list while the firewall also enforces the obfuscation block list — WordPress Core (or any plugin) stuck in that list stayed blocked invisibly. Unblock clears every HTTP block list, and the roster badge reflects the obfuscation-blocked state
- Core entries in the obfuscation block list now get the core exemption flow (whitelist, domain exceptions, same-site)

### 8.1.4
- **WordPress Core hard-block fixed:** a blocked core ignored the whitelist — whitelisting `api.wordpress.org` (or any host) now unblocks it for core requests while the rest of core stays blocked; per-source domain exceptions, global allowed domains and the same-site exception apply to core in all three firewall layers
- **Whitelist buttons fixed:** Whitelist WordPress / reCAPTCHA no longer insert a stray blank first line into the whitelist textarea

### 8.1.3
- Fixed stray "Thank you for creating with WordPress." footer text inside plugin pages (extra closing `</div>` in the Bad Potential panel broke the layout)
- New plugin description on the Plugins page
- Translation template (.pot) regenerated correctly from source — header syntax repaired, 300+ current strings

### 8.1.2
- **Domains button fixed:** the page footer containing the domain modal was never rendered, so the button did nothing; also fixed a JS scope error in the modal save handler
- **Blocked MU-plugins slipping through fixed:** the roster lists MU-plugins as `mu-name` while the tracer reported `name.php` — tracer now uses roster-compatible naming and every firewall layer matches all naming variants (`name`, `name.php`, `mu-name`)
- **Same-site loopback fixed:** the frontend guard had no same-site exception, so internal/localhost requests from blocked plugins were blocked even with "Allow Same-Site" enabled; Hard Block Mode now respects the exception too
- Log entries for whitelist/blacklist/core verdicts now record the real source plugin

### 8.1.1
- **Enforcement net:** every non-exception ALLOWED verdict is re-verified against the block lists and flipped to BLOCKED when the source is blocked — the log and the block list can no longer disagree
- **Hard Block Mode:** new setting that default-denies every plugin/theme/unknown source not explicitly on the Allowed list (catches unknown and hijacked plugins; WordPress core stays allowed)
- **Stable block lists:** atomic `REPLACE INTO` writes (no more empty-list window from DELETE+INSERT) plus read-back verification on every block/unblock
- Plugin check fixes: single `wp_parse_url()` wrapper in the cURL guard, prepared `%i` table rename, removed dead `class-helpers.php`

### 8.1.0
- **Strict blocking fix:** plugins blocked on the HTTP Firewall page are now actually blocked — the AJAX block/unblock buttons previously wrote to option names the firewall never read, so blocked plugins passed through and were logged as ALLOWED
- **Explicit block now wins** over the domain whitelist, allowed-domain lists and WordPress core hosts; the domain blacklist beats the whitelist
- **cURL guard fixed:** it read option names that were never written (blocks now apply to raw cURL too), and a fatal `wp_wp_parse_url()` call was removed
- **Guards loaded again:** the cURL guard and frontend guard are required by the main plugin, so `WON2_MU_ACTIVE` is defined and rewritten extensions keep working
- Same-site exception applies to blocked plugins only; pre-empted requests from other handlers are respected
- **Prefix rename:** `wfw` → `won1`, `wondalizer`/`wondalizer_fw` → `won2` for all functions, classes, options, transients and hooks (text domain, folder and `wondalizer-fw-curl-guard.php` filename unchanged); all legacy option names and the log table are migrated automatically
- All admin CSS/JS moved to enqueued assets (no inline scripts/styles); removed `time()` cache-busting from enqueues
- Fixed "Settings saved" notice not displaying; fixed About-page escaping; contributors list includes the owner's WordPress.org username
- Added one-time, self-dismissing donation notices after 1 and 2 weeks of usage

### 7.0.7
- Fixed admin CSS/JS not loading on all plugin pages
- Fixed Cron Firewall stat box layout
- Added Same-Site Connection Control for cache plugin compatibility
- Added cURL Cache logging option
- Protected plugin from appearing in its own Bad Potential list
- Fixed all WordPress Plugin Check errors (nonce verification, escaping, redirects, parse_url)
- Updated readme and translation template for WordPress.org release

### 7.0.6
- Improved server stability and reduced code redundancy
- Fixed activation progress box and streamlined initialization

### 6.8.0
- Resolved PHP regex double backslash escape parsing issue
- Fixed undefined variable notices in logger
- Replaced legacy queries with secure parameters
- Synchronized MU template signatures

### 6.7.7
- Fixed 503 errors on blocked HTTP requests
- Fixed PHP 8 TypeError with null timeouts
- Improved early-loading sequence

### 6.7.6
- Improved WordPress core request detection
- Fixed white screen issues in admin initialization
- Added bulletproof asset loading

### 6.7.0
- Initial release with HTTP/cURL firewall
- Email firewall implementation
- cURL cache engine and obfuscation detection

---

## 🤝 Support

- **Website:** [https://wondalizer.com](https://wondalizer.com)
- **Plugin URI:** [https://psycholatic.com/wondalizer-external-firewall](https://psycholatic.com/wondalizer-external-firewall)
- **WordPress Support Forums:** Use the official WordPress plugin support forum
- **Issues:** Report bugs via the WordPress support system

---

## 💝 Donate

If this plugin helps protect your site, consider supporting its development:

- **PayPal:** [https://www.paypal.com/donate/?hosted_button_id=XSMXZGDC997UY](https://www.paypal.com/donate/?hosted_button_id=XSMXZGDC997UY)
- **In-plugin:** Visit the **About** tab for the donate button

---

## 🎵 About the Author

**Wondalizer** — Music producer, WordPress developer, and security enthusiast.

- [🎧 HearThis.at](https://app.hearthis.at/dealazer/)
- [🌐 Website](https://wondalizer.com)

---

## 📄 License

This plugin is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.


## External Services

This plugin does not transmit data to external third-party services, does not load any remote assets (scripts, styles, images, fonts, iframes), and requires no external account.  
All request blocking, logging, and domain filtering is performed locally on your WordPress server.

The plugin may contact the following services **only under these conditions**:

- **WordPress.org** (`api.wordpress.org`, `downloads.wordpress.org`) — only if your WordPress installation already makes core update checks; this plugin does not initiate these requests.
- **Plugin/theme update servers** — only if a blocked plugin attempts its own update check; the plugin intercepts but does not forward the request.

No personal data, site URLs, or user information is sent to the plugin author or any external API.

