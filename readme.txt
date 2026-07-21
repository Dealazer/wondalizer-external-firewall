=== Wondalizer External Firewall ===
Contributors: dealazer, wondalizer
Donate link: https://www.paypal.com/donate/?hosted_button_id=XSMXZGDC997UY
Tags: firewall, security, internal http blocker, email firewall, obfuscation-detection
Requires at least: 6.4
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 8.1.8
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Advanced external request firewall for WordPress with cURL, socket, and email. Intruder prevention for hijacked plugins.

== Description ==

Wondalizer External Firewall is a powerful security plugin designed to protect your WordPress site from unwanted external connections, email interception, malicious cron jobs, and obfuscated code injection.

= Key Features =

* **HTTP/cURL Firewall** — Block or allow external HTTP requests with per-plugin and per-theme granular control
* **Email Firewall** — Prevent email interception and unauthorized mail sending from plugins and themes
* **Cron Firewall** — Block or allow specific cron hooks from executing external HTTP requests
* **cURL Cache Engine** — Physically rewrite plugin/theme PHP files to intercept cURL, fsockopen, stream_socket_client, and mail() calls
* **Obfuscation Detection (Bad Potential)** — Detect and score base64-encoded, hex-encoded, and other obfuscated code patterns
* **Extension Rewriting** — Automatically rewrite plugin/theme methods to use the firewall interceptors
* **Full Logging** — Comprehensive logging with circuit breaker protection and configurable retention
* **Domain Whitelist/Blacklist** — Manage allowed and blocked domains with wildcard support
* **Same-Site Exception** — Allow blocked plugins to still access your own domain (required for cache plugins)
* **Hard Block Mode** — Optional default-deny mode: only explicitly allowed plugins/themes can make external HTTP requests; unknown or hijacked sources are blocked automatically
* **Block Enforcement Net** — Every allowed verdict is re-verified against the block lists so a blocked plugin can never be logged or treated as allowed
* **WordPress Core Detection** — Automatically detects and classifies WordPress core requests
* **Dashboard Widget** — Real-time statistics and activity feed
* **MU-Plugin Support** — Early boot protection via must-use plugin for maximum security

= Security =

* Blocks unauthorized external HTTP requests at the WordPress level before they leave the server
* Prevents email interception by third-party plugins and themes
* Detects obfuscated code patterns in plugins and themes with threat scoring
* Cron firewall prevents blocked plugins from running external requests during scheduled tasks
* Provides detailed logging for security auditing with configurable retention
* Circuit breaker pattern prevents database overload during high traffic
* Same-site exception ensures cache plugins continue to function even when blocked externally

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/wondalizer-external-firewall/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Navigate to 'External Firewall' in the admin menu to configure settings
4. (Optional) Install the MU-plugin for early boot protection via the Settings tab

== Frequently Asked Questions ==

= Does this plugin block WordPress core updates? =

No. The plugin automatically detects WordPress core requests (including api.wordpress.org, downloads.wordpress.org, and planet.wordpress.org) and classifies them appropriately. Core functionality is never blocked.

= Will this break my plugins? =

The plugin includes a whitelist system, extension rewriting, and same-site exception for cache plugins. You can allow specific domains or disable blocking for specific plugins. The obfuscation detection is read-only by default.

= How does the logging work? =

The plugin uses a circuit breaker pattern — if the database is unavailable, it falls back to buffered logging. Logs are stored in the WordPress database with automatic cleanup based on your retention settings.

= Can I block specific domains? =

Yes. Use the Domain Management section in the admin panel to add domains to the whitelist or blacklist. Wildcards like *.tracker.com are supported.

= What is Hard Block Mode? =

Hard Block Mode (Settings → Global Blocking Behaviors) is a default-deny mode: every plugin, theme, drop-in or unknown source that is not explicitly on the Allowed list is blocked from external HTTP — including unknown or hijacked plugins that never appear on the roster. WordPress core stays allowed. To let a plugin through, mark it "Allowed" on the HTTP Firewall page first.

= What is the Same-Site exception? =

When enabled (default), blocked plugins can still make HTTP requests to your own domain. This is essential for cache plugins like WP Rocket, W3 Total Cache, and LiteSpeed Cache that need to warm caches or generate static files.

= What is the Cron Firewall? =

The Cron Firewall blocks all external HTTP requests made during WordPress cron execution (wp-cron.php) unless explicitly whitelisted. This prevents blocked plugins from bypassing the firewall via scheduled tasks.

= What is Bad Potential? =

Bad Potential detects obfuscated code patterns (base64, hex encoding, eval, etc.) in plugins and themes. It provides a threat score to help you identify potentially malicious extensions.

== Screenshots ==

1. Dashboard overview with real-time statistics and status boxes
2. HTTP Firewall settings with per-extension blocking controls
3. Email Firewall configuration with allow/block lists
4. Cron Firewall with scheduled event management
5. Obfuscation detection results with threat scoring
6. cURL Cache extension rewriting interface
7. Logging and activity feed with color-coded entries
8. Domain whitelist and blacklist management

== Plugin Check & Compliance Notes ==

This section documents how previously flagged static-analysis items are handled:

* **No remote file loading — the plugin calls no servers at all.** All CSS/JS is bundled locally in `assets/` and served via `wp_enqueue_*`. The plugin initiates zero outbound requests of its own, loads no images/scripts/iframes/fonts from any remote host, requires no account, no API key and no connection to the author's servers. The domain strings flagged by automated scans are local *text data*, never fetched:
  - `includes/render/class-render-settings.php` — a `data-domains="google.com|gstatic.com|recaptcha.net"` attribute on the "Auto-Whitelist reCAPTCHA Domains" button; clicking it only copies those names into the local whitelist textarea.
  - `includes/class-admin-actions.php` — the same three names as a PHP array used when saving that whitelist preset.
  - `includes/class-scan.php` — `placeholder.com`/`placeholder.org` inside `FALSE_POSITIVE_DOMAINS`, a filter list so the scanner ignores documentation-style domains in scanned code.
* **cURL usage is the firewall service itself (like Akismet's server calls, but in reverse — nothing is ever sent to us).** `wondalizer-fw-curl-guard.php` is a pass-through shim: it services cURL handles that belong to *other* plugins/themes whose code was rewritten — only with the administrator's explicit per-extension consent — to route through this firewall. Every URL is vetted through the WordPress HTTP API's own `pre_http_request` filter *before* any handle is executed. The remaining raw `\curl_exec($ch)` cannot be converted to `wp_remote_*()`: PHP exposes no API to read back the options (headers, POST fields, SSL settings, auth, timeouts) the originating plugin already set on its handle, so reconstructing the request through the HTTP API would silently corrupt that plugin's requests. The `http://won1-blocked.invalid/` URL is an intentionally unresolvable `.invalid` placeholder used to neutralize blocked handles — it is never a real call.
* **ABSPATH usage** — `ABSPATH` is only used to recognize WordPress core files when tracing which extension initiated a request. No files are loaded from remote or hardcoded paths.
* **Enqueued assets only** — All admin CSS and JavaScript is served via `wp_enqueue_style()`/`wp_enqueue_script()` from `assets/admin.css` and `assets/admin.js`, with configuration passed through `wp_localize_script()`. No inline `<script>` or `<style>` output remains in the admin pages.
* **Unique prefixes** — All functions, classes, options, transients, constants and cron hooks use the `won1_` (firewall domain data) or `won2_` (functions, classes, options) prefixes. Legacy `wfw_*` and `wondalizer_*` option names are migrated automatically on first run.

== Changelog ==

= 8.1.8 =
* Reviewer compliance: expanded the readme documentation proving the plugin loads no remote files and calls no servers — the flagged domain strings (google.com, gstatic.com, recaptcha.net, placeholder.com) are local whitelist-preset text data and a scanner ignore-list, never fetched
* Reviewer compliance: documented the cURL shim inline and in the readme — it only executes other plugins' cURL handles after each URL passes the WordPress HTTP API 'pre_http_request' firewall check; the plugin itself initiates no remote requests
* Added inline justification comments at every raw cURL call site for future automated reviews

= 8.1.7 =
* Fixed the Domains button (per-plugin domain exceptions) having no effect on the frontend: the guard layer ran before the main firewall and its blocked branch did not honor the Domains modal exceptions or the global allowed domains — both exception lists are now honored in all three firewall layers
* Fixed must-use plugins being unscannable: the roster registers them as "mu-<name>" (single files, not directories), which the scan engine could not resolve to a path — scanning, the Domains modal and rewrite now work for MU plugins
* Domains saved via the Domains modal are now normalized (lowercase, no scheme, no trailing slash, no empty lines) so they always match; older saved entries are normalized on read
* Removed a leftover unused render file (duplicate cron panel markup that was never called)
* Readme short description shortened to comply with the 150-character limit

= 8.1.6 =
* Fixed WordPress Core staying blocked after roster unblock: older versions had listed core under several names ('core', 'wp-core', 'wordpress-core') and the firewall blocked on ANY of them while Unblock removed only 'wordpress-core' — all layers now treat every core alias as one entity, and Unblock removes all aliases from every block list
* Core blocking/unblocking now runs through the exact same code path as plugins and themes (the separate special-case branch was removed); core keeps its whitelist/domain/same-site exemptions when blocked
* The roster badge now matches the firewall exactly (obfuscation list + core aliases)
* Form-post block/unblock now also clears the full object cache so changes apply everywhere immediately

= 8.1.5 =
* Fixed WordPress Core (or any plugin) staying blocked after being unblocked on the HTTP Firewall tab: the single-row Unblock button only removed the entry from the plugin block list, while the firewall also enforces the obfuscation block list — Unblock now removes the entry from every HTTP block list, and the roster badge reflects the obfuscation-blocked state so the UI matches the firewall
* A core entry present in the obfuscation block list now goes through the core exemption flow (whitelist, domain exceptions, same-site) instead of being hard-blocked without them

= 8.1.4 =
* Fixed WordPress Core being hard-blocked: a blocked core ignored the whitelist entirely — whitelisting api.wordpress.org (or any host) now unblocks it for core requests while the rest of core stays blocked; per-source domain exceptions, global allowed domains and the same-site exception also apply to core (in all three firewall layers)
* Fixed the Whitelist WordPress / reCAPTCHA buttons inserting a stray blank first line into the whitelist textarea (splitting an empty textarea produced one empty entry)

= 8.1.3 =
* Fixed the stray "Thank you for creating with WordPress." admin footer text appearing inside the plugin pages: an extra closing div in the Bad Potential panel broke the page layout (all panels now have balanced markup)
* Updated the plugin description shown on the Plugins page
* Regenerated the translation template (.pot) correctly: all 300+ current strings extracted from source, header syntax repaired
* Removed the last plugin-check warning (unused class-helpers.php with a direct database call was deleted in 8.1.1)

= 8.1.2 =
* Fixed the Domains button on the HTTP Firewall page doing nothing: the page footer (which contains the domain modal) was never rendered, so the modal could not open; also fixed a JavaScript scope error in the modal's save handler
* Fixed blocked plugins still being allowed: MU-plugins were listed on the roster as "mu-name" while the request tracer reported "name.php", so they never matched the block list — the tracer now uses roster-compatible naming and all firewall layers match folders against all naming variants (name, name.php, mu-name)
* Fixed same-site (loopback/localhost/internal) requests being blocked on the frontend even with "Allow Same-Site" enabled: the frontend guard was missing the same-site exception entirely; Hard Block Mode now also respects the same-site exception setting
* Fixed log entries showing the wrong/unknown plugin for whitelist, blacklist and core-host verdicts (the source was not recorded for those entries)

= 8.1.1 =
* Fixed blocked plugins still being logged as ALLOWED: added a final enforcement net that re-verifies every non-exception ALLOWED verdict against the block lists and flips it to BLOCKED, so the log and the block list can never disagree
* Added Hard Block Mode (Settings): default-deny for every plugin, theme and unknown source that is not explicitly on the Allowed list — catches unknown or hijacked plugins that never appear on the roster; WordPress core stays allowed
* Block list writes are now atomic (REPLACE INTO instead of DELETE+INSERT, which left a window where lists read as empty) and every block/unblock write is verified with a read-back check
* Fixed plugin check errors: parse_url() fallbacks in the cURL guard replaced with a single wp_parse_url() wrapper
* Fixed plugin check warnings: the one-time log-table rename now uses $wpdb->prepare() with %i placeholders; removed the unused class-helpers.php file

= 8.1.0 =
* Fixed blocked plugins being logged as ALLOWED and passing through the firewall: the AJAX block/unblock buttons now write to the same options the firewall actually reads (they previously wrote to won2_blocked / won2_blocked_email / won2_blocked_obs, which nothing checked)
* Strict mode: an explicit plugin block now wins over the domain whitelist, allowed-domain lists and WordPress core hosts; the domain blacklist now beats the whitelist
* Fixed the cURL guard reading option names that were never written (it now reads the canonical settings and block lists, so blocks from the HTTP Firewall page apply to raw cURL too)
* Fixed fatal error in the cURL guard caused by a call to the undefined function wp_wp_parse_url()
* The cURL guard and frontend guard are now loaded by the main plugin again (WON2_MU_ACTIVE is defined, MU status shows correctly)
* Same-site exception in the guard layer now applies to blocked plugins only
* Requests already short-circuited by other handlers (pre_http_request / pre_wp_mail) are respected instead of being re-evaluated and mis-logged
* Automatic migration of all legacy option names (wondalizer_* and wfw_* to won2_* and won1_*), including the historically wrong block-option names, plus renaming of the logs table
* All admin CSS/JS moved to enqueued assets (no inline script/style output) and removed time() cache-busting from the script version
* Renamed all code prefixes: wfw to won1, wondalizer/wondalizer_fw to won2 (text domain, plugin folder and the wondalizer-fw-curl-guard.php filename are unchanged)
* Fixed the "Settings saved" admin notice not displaying (the redirect was missing the message nonce)
* Fixed output escaping on the About page (PHP_VERSION, extension status, rule counts)
* Contributors list now includes the plugin owner's WordPress.org username
* Added a one-time, self-dismissing donation notice shown once after 1 week and once after 2 weeks of usage, linking to the About page

= 7.1 =
* Fixed WordPress Core blocking/unblocking in HTTP firewall
* Fixed source detection to return 'wordpress-core' for all core files
* Fixed whitelist/blacklist domain normalization (lowercase, strip protocol, strip trailing slash)
* Fixed blocked_obfuscation not being cleared on unblock
* Added ajax_test_block endpoint for testing blocking status
* Added ajax_clear_all_obs endpoint to clear all obfuscation blocks
* Fixed cache invalidation between MU template and main firewall
* Fixed MissingTranslatorsComment plugin check error
* Fixed EscapeOutput plugin check error on wp_nonce_field
* Fixed PreparedSQL warning in roster log queries

= 7.0.8 =
* Fixed all WordPress Plugin Check errors and warnings to zero
* Replaced error_log() with transient-based debug logging
* Replaced all direct database queries with standard WordPress option APIs
* Added object caching to logger stats and recent queries
* Refactored admin actions to sanitize all POST data before processing
* Added nonce verification to admin message display
* Replaced is_writable() with WP_Filesystem for plugin check compliance
* Used %i identifier placeholder for all custom table queries
* Added proper PHPCS ignore annotations only for core hook names and debug_backtrace
* Updated readme.txt stable tag and short description for WordPress.org compliance

= 7.0.7 =
* Fixed admin CSS/JS not loading on all plugin pages by using slug-based hook matching
* Fixed Cron Firewall stat box layout with consistent flexbox styling
* Added Same-Site Connection Control setting with cache plugin notice
* Added cURL Cache logging option to log all intercepted rewrite calls
* Protected Wondalizer External Firewall from appearing in Bad Potential list
* Fixed all WordPress Plugin Check errors: parse_url, wp_redirect, nonce verification, escaping
* Fixed all WordPress Plugin Check warnings: debug_backtrace, direct DB queries prepared properly
* Updated readme.txt and plugin headers for WordPress.org release compliance
* Updated translation template (.pot) with all new strings

= 7.0.6 =
* Improved server stability and reduced code redundancy
* Fixed activation progress box and streamlined initialization
* Enhanced bbPress compatibility and forum topic reply handling
* Fixed admin avatar and menu loading issues

= 6.8.0 =
* Resolved PHP regex double backslash escape parsing issue preventing successful file rewriting in standard environments.
* Fixed undefined variable notices in class-logger.php log_always method.
* Replaced legacy %i queries with secure raw parameters for backward compatibility with WordPress versions prior to 6.2.
* Synchronized mu-template.php signatures with class-guard.php to avoid early initialization errors.
* Patched input host comparison routines to gracefully strip standard developer ports.
* Resolved missing admin.js asset warning in enqueued asset declarations.

= 6.7.7 =
* Fixed Service Unavailable (503) error occurring when an HTTP request was blocked and failed to parse properly by consuming themes.
* Fixed fatal error causing 503 errors related to WP 5.5+ PHPMailer class exception changes.
* Fixed PHP 8 TypeError strictly relating to null timeouts being implicitly passed to native network streams.
* Significantly improved early-loading sequence to safeguard Cache Engine functions from triggering undefined errors.

= 6.7.6 =
* Improved WordPress core request detection
* Enhanced interceptor for planet.wordpress.org and other core endpoints
* Fixed white screen issues in admin initialization
* Merged UI improvements from previous versions
* Added bulletproof asset loading
* Fixed CSS/JS modal consistency
* Improved source tracing for core files

= 6.7.5 =
* Added domain modal management
* Improved CSS styling for all admin sections
* Enhanced logging with forced planet.wordpress.org visibility

= 6.7.0 =
* Initial release with HTTP/cURL firewall
* Email firewall implementation
* cURL cache engine
* Obfuscation detection
* Extension rewriting system

== Upgrade Notice ==

= 8.1.2 =
Fixes the Domains button, MU-plugin block-list matching (blocked plugins slipping through), and same-site loopback requests being wrongly blocked on the frontend.

= 8.1.1 =
Enforcement fix: blocked plugins can no longer slip through as ALLOWED, atomic block-list writes, and a new optional Hard Block Mode that default-denies everything not explicitly allowed.

= 8.1.0 =
Important strict-mode fix: plugins blocked on the HTTP Firewall page are now actually blocked everywhere (HTTP API, cURL, sockets, cron) instead of being logged as allowed. All settings are migrated automatically.

= 7.0.8 =
Critical release fixing all WordPress Plugin Check errors and warnings for zero-compliance release readiness.

= 7.0.7 =
Important upgrade fixing admin CSS loading, adding same-site exception for cache plugins, cURL cache logging, and resolving all WordPress Plugin Check errors for release readiness.

= 6.8.0 =
Important upgrade optimizing execution patterns, correcting scanning heuristics, and resolving structural warnings.

== Arbitrary section ==

= Support =

For support, visit https://wondalizer.com or contact through the WordPress support forums.

= Donations =

If you find this plugin useful, consider supporting development through the plugin settings page or via PayPal.
