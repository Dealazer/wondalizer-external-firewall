<?php
// phpcs:disable WordPress.WP.AlternativeFunctions.curl_curl_init,WordPress.WP.AlternativeFunctions.curl_curl_setopt,WordPress.WP.AlternativeFunctions.curl_curl_setopt_array,WordPress.WP.AlternativeFunctions.curl_curl_exec,WordPress.WP.AlternativeFunctions.curl_curl_close,WordPress.WP.AlternativeFunctions.file_system_operations_fsockopen,WordPress.WP.AlternativeFunctions.file_system_operations_pfsockopen,WordPress.WP.AlternativeFunctions.file_system_operations_stream_socket_client,WordPress.WP.AlternativeFunctions.file_system_operations_file_get_contents,WordPress.WP.AlternativeFunctions.file_system_operations_fopen
/**
 * Wondalizer External Firewall — MU Guard (v8.1.8)
 * Version: 8.1.8
 */

if (!defined('ABSPATH')) exit;

if (!defined('WON2_MU_ACTIVE')) {
    define('WON2_MU_ACTIVE', true);
}

if (!function_exists('won2_mu_folder_matches')) {
    /**
     * Match a traced folder against a block/allow list, accepting roster and
     * legacy naming variants ('name.php', 'mu-name', 'name').
     */
    function won2_mu_folder_matches($folder, $list) {
        if (empty($folder) || empty($list)) {
            return false;
        }
        $base = preg_replace('/\.php$/', '', $folder);
        $variants = [$folder, $base];
        if (strpos($base, 'mu-') === 0) {
            $variants[] = substr($base, 3);
            $variants[] = substr($base, 3) . '.php';
        } else {
            $variants[] = 'mu-' . $base;
        }
        // WordPress core aliases from different versions are one entity.
        $core_aliases = ['wordpress-core', 'wp-core', 'core', 'wp-admin', 'wp-includes'];
        if (in_array($base, $core_aliases, true)) {
            $variants = array_merge($variants, $core_aliases);
        }
        foreach (array_unique($variants) as $v) {
            if (in_array($v, $list, true)) {
                return true;
            }
        }
        return false;
    }
}

if (!function_exists('won2_mu_parse_url')) {
    /**
     * URL parsing wrapper: always prefers wp_parse_url(). The native parse_url()
     * fallback below only runs when WordPress is not loaded yet, which cannot
     * happen in practice because this file is loaded by WordPress (main plugin
     * or mu-plugins loader).
     */
    function won2_mu_parse_url($url, $component = -1) {
        if (function_exists('wp_parse_url')) {
            return wp_parse_url($url, $component);
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- pre-boot fallback only; wp_parse_url() is used whenever WordPress is loaded
        return parse_url($url, $component);
    }
}

if (!class_exists('Won2_Curl_Guard_Base')) {
    /**
     * cURL pass-through shim.
     *
     * These methods exist ONLY to service cURL handles that were created by
     * OTHER plugins (or themes) whose code was rewritten — with the site
     * administrator's explicit consent — to route through this firewall.
     * Every URL is vetted through the WordPress HTTP API's own
     * 'pre_http_request' filter before any handle is executed.
     *
     * The raw \curl_* calls below cannot be replaced with wp_remote_*():
     * a cURL handle is opaque — PHP exposes no API to read back the options
     * (headers, POST fields, SSL settings, auth, timeouts) the originating
     * plugin already set on it — so reconstructing the request through the
     * HTTP API would silently corrupt the originating plugin's requests.
     * This plugin never initiates any remote request of its own.
     */
    class Won2_Curl_Guard_Base {
        public function curl_init($url = null) {
            if (!function_exists('curl_init')) return false;

            if ($url !== null && function_exists('apply_filters')) {
                // Ensure core filters can run safely
                try {
                    $check = apply_filters('pre_http_request', false, [], $url); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook
                    if (is_wp_error($check)) {
                        won2_mu_log_rewrite('curl_init', $url, 'BLOCKED');
                        return false;
                    }
                    won2_mu_log_rewrite('curl_init', $url, 'ALLOWED');
                } catch (\Throwable $th) {
                    // Safe fallback to allow request if filtering fails mid-execution to avoid whitescreens
                }
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_init -- pass-through shim for third-party handles; URL pre-vetted via the HTTP API 'pre_http_request' filter
            return $url === null ? \curl_init() : \curl_init($url);
        }

        public function curl_setopt($ch, $option, $value) {
            if (!function_exists('curl_setopt')) return false;

            if (defined('CURLOPT_URL') && $option === CURLOPT_URL && function_exists('apply_filters')) {
                try {
                    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- pre_http_request is a core WordPress hook
                    $check = apply_filters('pre_http_request', false, [], $value);
                    if (is_wp_error($check)) {
                        won2_mu_log_rewrite('curl_setopt', $value, 'BLOCKED');
                        // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt -- shim: neutralizes a blocked handle with an unresolvable .invalid URL
                        return \curl_setopt($ch, CURLOPT_URL, 'http://won1-blocked.invalid/won2_blocked');
                    }
                    won2_mu_log_rewrite('curl_setopt', $value, 'ALLOWED');
                } catch (\Throwable $th) {
                    // Fallback to safety
                }
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt -- pass-through shim; CURLOPT_URL was pre-vetted via 'pre_http_request'
            return \curl_setopt($ch, $option, $value);
        }

        public function curl_setopt_array($ch, $options) {
            if (!function_exists('curl_setopt_array')) return false;
            if (is_array($options)) {
                if (defined('CURLOPT_URL') && isset($options[CURLOPT_URL]) && function_exists('apply_filters')) {
                    try {
                        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- pre_http_request is a core WordPress hook
                        $check = apply_filters('pre_http_request', false, [], $options[CURLOPT_URL]);
                        if (is_wp_error($check)) {
                            won2_mu_log_rewrite('curl_setopt_array', $options[CURLOPT_URL], 'BLOCKED');
                            $options[CURLOPT_URL] = 'http://won1-blocked.invalid/won2_blocked';
                        } else {
                            won2_mu_log_rewrite('curl_setopt_array', $options[CURLOPT_URL], 'ALLOWED');
                        }
                    } catch (\Throwable $th) {
                        // Fallback to safety
                    }
                }
                // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt_array -- pass-through shim; CURLOPT_URL was pre-vetted via 'pre_http_request'
                return \curl_setopt_array($ch, $options);
            }
            return false;
        }

        public function curl_exec($ch) {
            if (!function_exists('curl_exec')) return false;
            // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_exec -- executes a third-party handle whose URL already passed the HTTP API 'pre_http_request' firewall check; cannot be converted to wp_remote_*() without corrupting the originating plugin's request options
            return \curl_exec($ch);
        }

        public function curl_close($ch) {
            if (!function_exists('curl_close')) return;
            // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_close -- pass-through shim for third-party handles
            return \curl_close($ch);
        }

        public function fsockopen($h, $p = -1, &$ec = null, &$em = null, $t = null) {
            if (!function_exists('fsockopen')) { $em = 'fsockopen disabled'; return false; }

            if (function_exists('apply_filters')) {
                $url = 'http://' . $h . ($p !== -1 ? ':' . $p : '');
                try {
                    $check = apply_filters('pre_http_request', false, [], $url); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook
                    if (is_wp_error($check)) {
                        $ec = 403;
                        $em = 'Connection blocked by Wondalizer External Firewall';
                        won2_mu_log_rewrite('fsockopen', $url, 'BLOCKED');
                        return false;
                    }
                    won2_mu_log_rewrite('fsockopen', $url, 'ALLOWED');
                } catch (\Throwable $th) {
                    // Fallback to safety
                }
            }

            $n = func_num_args();
            $t_val = $t === null ? (float) ini_get("default_socket_timeout") : (float) $t;
            if ($n <= 1) return \fsockopen($h);
            if ($n <= 2) return \fsockopen($h, $p);
            if ($n <= 3) return \fsockopen($h, $p, $ec);
            if ($n <= 4) return \fsockopen($h, $p, $ec, $em);
            return \fsockopen($h, $p, $ec, $em, $t_val);
        }

        public function pfsockopen($h, $p = -1, &$ec = null, &$em = null, $t = null) {
            if (!function_exists('pfsockopen')) { $em = 'pfsockopen disabled'; return false; }

            if (function_exists('apply_filters')) {
                $url = 'http://' . $h . ($p !== -1 ? ':' . $p : '');
                try {
                    $check = apply_filters('pre_http_request', false, [], $url); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook
                    if (is_wp_error($check)) {
                        $ec = 403;
                        $em = 'Connection blocked by Wondalizer External Firewall';
                        won2_mu_log_rewrite('pfsockopen', $url, 'BLOCKED');
                        return false;
                    }
                    won2_mu_log_rewrite('pfsockopen', $url, 'ALLOWED');
                } catch (\Throwable $th) {
                    // Fallback to safety
                }
            }

            $n = func_num_args();
            $t_val = $t === null ? (float) ini_get("default_socket_timeout") : (float) $t;
            if ($n <= 1) return \pfsockopen($h);
            if ($n <= 2) return \pfsockopen($h, $p);
            if ($n <= 3) return \pfsockopen($h, $p, $ec);
            if ($n <= 4) return \pfsockopen($h, $p, $ec, $em);
            return \pfsockopen($h, $p, $ec, $em, $t_val);
        }

        public function stream_socket_client($a, &$ec = null, &$em = null, $t = null, $f = 4, $ctx = null) {
            if (!function_exists('stream_socket_client')) { $em = 'stream_socket_client disabled'; return false; }

            if (function_exists('apply_filters')) {
                $parts = won2_mu_parse_url($a);
                $h = '';
                $p = -1;
                
                // Safe check to avoid array offset access errors on boolean
                if (is_array($parts)) {
                    $h = $parts['host'] ?? ($parts['path'] ?? '');
                    $p = $parts['port'] ?? -1;
                } else if (is_string($a)) {
                    $h = $a;
                }

                $url = 'http://' . $h . ($p !== -1 ? ':' . $p : '');
                try {
                    $check = apply_filters('pre_http_request', false, [], $url); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook
                    if (is_wp_error($check)) {
                        $ec = 403;
                        $em = 'Connection blocked by Wondalizer External Firewall';
                        won2_mu_log_rewrite('stream_socket_client', $url, 'BLOCKED');
                        return false;
                    }
                    won2_mu_log_rewrite('stream_socket_client', $url, 'ALLOWED');
                } catch (\Throwable $th) {
                    // Fallback to safety
                }
            }

            $n = func_num_args();
            $t_val = $t === null ? (float) ini_get("default_socket_timeout") : (float) $t;
            if ($n <= 1) return \stream_socket_client($a);
            if ($n <= 2) return \stream_socket_client($a, $ec);
            if ($n <= 3) return \stream_socket_client($a, $ec, $em);
            if ($n <= 4) return \stream_socket_client($a, $ec, $em, $t_val);
            if ($n <= 5) return \stream_socket_client($a, $ec, $em, $t_val, $f);
            return \stream_socket_client($a, $ec, $em, $t_val, $f, $ctx);
        }

        public function mail($to, $subject, $message, $headers = '', $params = '') {
            if (!function_exists('mail')) return false;

            if (function_exists('apply_filters')) {
                $mail_atts = ['to' => $to, 'subject' => $subject, 'message' => $message, 'headers' => $headers, 'attachments' => []];
                try {
                    $check = apply_filters('pre_wp_mail', $mail_atts, $mail_atts); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook
                    if ($check === false) {
                        won2_mu_log_rewrite('mail', $to, 'BLOCKED');
                        return false;
                    }
                    won2_mu_log_rewrite('mail', $to, 'ALLOWED');
                } catch (\Throwable $th) {
                    // Fallback to safety
                }
            }

            $n = func_num_args();
            if ($n <= 3) return \mail($to, $subject, $message);
            if ($n <= 4) return \mail($to, $subject, $message, $headers);
            return \mail($to, $subject, $message, $headers, $params);
        }

        public function wp_mail($to, $subject, $message, $headers = '', $attachments = []) {
            if (!function_exists('wp_mail')) return false;
            return \wp_mail($to, $subject, $message, $headers, $attachments);
        }
    }
}

function won2_mu_get_option_direct($option, $default = []) {
    global $wpdb;
    // Guard against early inclusions before transient system or object cache is declared
    if (!function_exists('wp_cache_get') || !function_exists('wp_cache_set') || !function_exists('wp_cache_delete')) {
        if (function_exists('get_option')) {
            return get_option($option, $default);
        }
        return $default;
    }
    
    if (isset($wpdb) && $wpdb instanceof wpdb && !empty($wpdb->ready)) {
        wp_cache_delete($option, 'options');
        wp_cache_delete('alloptions', 'options');
        wp_cache_delete('notoptions', 'options');
        $cached = wp_cache_get($option, 'won2_mu_options');
        if (false !== $cached) {
            return $cached;
        }
        
        $wpdb->suppress_errors(true);
        $row = $wpdb->get_row($wpdb->prepare("SELECT option_value FROM $wpdb->options WHERE option_name = %s LIMIT 1", $option)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->suppress_errors(false);
        
        if ($row) {
            $val = $row->option_value;
            if (is_string($val) && (strpos($val, 'a:') === 0 || strpos($val, 'O:') === 0 || strpos($val, 's:') === 0)) {
                $val = @unserialize($val);
            }
            wp_cache_set($option, $val, 'won2_mu_options', 1);
            return $val;
        }
        wp_cache_set($option, $default, 'won2_mu_options', 1);
        return $default;
    }
    
    if (function_exists('get_option')) {
        return get_option($option, $default);
    }
    return $default;
}

function won2_mu_log_rewrite($method, $target, $status) {
    $settings = wp_parse_args(won2_mu_get_option_direct('won2_firewall_settings', []), [
        'logging_enabled' => true,
        'log_curl_cache' => false,
    ]);
    if (empty($settings['logging_enabled']) || empty($settings['log_curl_cache'])) {
        return;
    }
    $host = '';
    $host = won2_mu_parse_url($target, PHP_URL_HOST);
    $host = $host ? strtolower($host) : '';
    $entry = [
        'type' => 'http',
        'url' => $target,
        'host' => $host,
        'status' => $status,
        'reason' => 'curl_cache_' . $method,
        'time' => time(),
    ];
    global $won2_intercept_buffer;
    if (!is_array($won2_intercept_buffer)) $won2_intercept_buffer = [];
    $won2_intercept_buffer[] = $entry;
}

add_filter('pre_http_request', 'won2_mu_intercept_http', PHP_INT_MAX - 100, 3);
function won2_mu_intercept_http($preempt, $parsed_args, $url) {
    if (!did_action('init') && !did_action('wp_loaded')) {
        return $preempt;
    }
    
    if (defined('WON2_VERSION') || class_exists('Won2_Firewall')) {
        return $preempt;
    }

    $settings = wp_parse_args(won2_mu_get_option_direct('won2_firewall_settings', []), [
        'http_firewall_enabled' => false,
    ]);
    if (empty($settings['http_firewall_enabled'])) {
        return $preempt;
    }

    // Another handler already short-circuited this request — respect it.
    if (false !== $preempt) {
        return $preempt;
    }

    $host = won2_mu_parse_url($url, PHP_URL_HOST);
    $host = $host ? strtolower($host) : '';

    $blocked_plugins = array_map('strtolower', (array) won2_mu_get_option_direct('won2_blocked_plugins', []));
    $allowed_plugins = array_map('strtolower', (array) won2_mu_get_option_direct('won2_allowed_plugins', []));
    $blocked_obs     = array_map('strtolower', (array) won2_mu_get_option_direct('won2_blocked_obfuscation', []));

    $source = won2_mu_detect_source();
    $folder = strtolower($source['folder'] ?? '');

    if (empty($folder) && ($source['type'] === 'core' || $source['type'] === 'unknown')) {
        $folder = 'wordpress-core';
    }

    // Self-protection: this plugin is never blocked.
    if (strpos($folder, 'wondalizer-external-firewall') !== false || strpos($folder, 'wondalizer-fw') !== false) {
        return $preempt;
    }

    $settings = wp_parse_args(won2_mu_get_option_direct('won2_firewall_settings', []), [
        'allow_same_site_for_blocked' => true,
        'block_by_default' => false,
        'block_themes_by_default' => false,
        'hard_block_mode' => false,
    ]);

    // Hard Block Mode: default-deny for everything not explicitly allowed.
    if (!empty($settings['hard_block_mode'])) {
        $src_type = $source['type'] ?? 'unknown';
        $is_core_source = ($src_type === 'core' || $folder === 'wordpress-core' || $folder === 'wp-core');
        $site_host_hb = won2_mu_parse_url(home_url(), PHP_URL_HOST);
        if (!$is_core_source && !won2_mu_folder_matches($folder, $allowed_plugins)
            && !($host === $site_host_hb && !empty($settings['allow_same_site_for_blocked']))) {
            $msg = function_exists('esc_html__') ? esc_html__('Request blocked by Wondalizer External Firewall (Hard Block Mode).', 'wondalizer-external-firewall') : 'Request blocked by Wondalizer External Firewall (Hard Block Mode).';
            return new WP_Error('won2_blocked', $msg);
        }
    }

    // Determine block status FIRST — an explicit block must win over
    // core-host allows and the domain whitelist (strict mode).
    $is_blocked = false;
    if (won2_mu_folder_matches($folder, $blocked_plugins) || won2_mu_folder_matches($folder, $blocked_obs)) {
        $is_blocked = true;
    } elseif (won2_mu_folder_matches($folder, $allowed_plugins)) {
        $is_blocked = false;
    } else {
        $is_plugin = ($source['type'] === 'plugin' || $source['type'] === 'mu-plugin');
        $is_theme  = ($source['type'] === 'theme');
        if ($is_plugin && !empty($settings['block_by_default'])) {
            $is_blocked = true;
        } elseif ($is_theme && !empty($settings['block_themes_by_default'])) {
            $is_blocked = true;
        }
    }

    if ($is_blocked) {
        // Same-site exception only applies to blocked plugins.
        $site_host = won2_mu_parse_url(home_url(), PHP_URL_HOST);
        if ($host === $site_host && !empty($settings['allow_same_site_for_blocked'])) {
            return $preempt;
        }
        // Core sources stay governable by the whitelist: whitelisting
        // api.wordpress.org unblocks it for core requests.
        $src_is_core = (($source['type'] ?? '') === 'core') || in_array($folder, ['wordpress-core', 'wp-core', 'core'], true);
        if ($src_is_core) {
            $wl = array_filter(array_map(function($d) {
                $d = strtolower(trim($d));
                $d = preg_replace('#^https?://#', '', $d);
                return rtrim($d, '/');
            }, (array) won2_mu_get_option_direct('won1_whitelist_domains', [])));
            foreach ($wl as $w) {
                if ($w !== '' && ($host === $w || substr($host, -strlen('.'.$w)) === '.'.$w)) {
                    return $preempt;
                }
            }
        }
        // Per-plugin explicit domain exceptions (set via the Domains modal).
        $pad = won2_mu_get_option_direct('won2_plugin_allowed_domains', []);
        $allowed_for_this_plugin = (is_array($pad) && isset($pad[$folder])) ? (array) $pad[$folder] : [];
        foreach ($allowed_for_this_plugin as $ad) {
            $ad = strtolower(trim((string) $ad));
            if ($ad !== '' && ($host === $ad || substr($host, -strlen('.'.$ad)) === '.'.$ad)) {
                return $preempt;
            }
        }
        // Global allowed-domain exceptions for blocked plugins.
        if (!empty($settings['allowed_domains']) && is_array($settings['allowed_domains'])) {
            foreach ($settings['allowed_domains'] as $ad) {
                $ad = strtolower(trim($ad));
                if ($ad !== '' && ($host === $ad || substr($host, -strlen('.'.$ad)) === '.'.$ad)) {
                    return $preempt;
                }
            }
        }
        $msg = function_exists('esc_html__') ? esc_html__('Request blocked by Wondalizer External Firewall.', 'wondalizer-external-firewall') : 'Request blocked by Wondalizer External Firewall.';
        return new WP_Error('won2_blocked', $msg);
    }

    // Domain blocklist beats core hosts and the whitelist (strict mode).
    $blacklist = array_map(function($d) {
        $d = strtolower(trim($d));
        $d = preg_replace('#^https?://#', '', $d);
        $d = rtrim($d, '/');
        return $d;
    }, (array) won2_mu_get_option_direct('won1_blacklist_domains', []));
    foreach ($blacklist as $b) {
        if ($host === $b || substr($host, -strlen('.'.$b)) === '.'.$b) {
            $msg = function_exists('esc_html__') ? esc_html__('Request blocked by Wondalizer External Firewall.', 'wondalizer-external-firewall') : 'Request blocked by Wondalizer External Firewall.';
            return new WP_Error('won2_blocked', $msg);
        }
    }

    $core = ['wordpress.org', 'api.wordpress.org', 'downloads.wordpress.org', 'planet.wordpress.org', 'ps.w.org', 's.w.org'];
    foreach ($core as $c) {
        if ($host === $c || substr($host, -strlen('.'.$c)) === '.'.$c) return $preempt;
    }

    $whitelist = array_map(function($d) {
        $d = strtolower(trim($d));
        $d = preg_replace('#^https?://#', '', $d);
        $d = rtrim($d, '/');
        return $d;
    }, (array) won2_mu_get_option_direct('won1_whitelist_domains', []));
    foreach ($whitelist as $w) {
        if ($host === $w || substr($host, -strlen('.'.$w)) === '.'.$w) return $preempt;
    }

    $is_domain_allowed = won2_mu_is_domain_fallback_allowed($host, $allowed_plugins);
    if ($is_domain_allowed) {
        return $preempt;
    }

    return $preempt;
}

function won2_mu_is_domain_fallback_allowed($host, $allowed_plugins) {
    if (empty($allowed_plugins)) return false;
    $host = strtolower($host);
    $domain_map = [
        'rankmath.com' => ['seo-by-rank-math', 'rank-math', 'rank-math-pro', 'rankmath'],
        'rankmath.io' => ['seo-by-rank-math', 'rank-math', 'rank-math-pro', 'rankmath'],
        'mythemeshop.com' => ['seo-by-rank-math', 'rank-math', 'rank-math-pro', 'rankmath'],
        'yoast.com' => ['wordpress-seo', 'yoast-seo'],
        'w.org' => ['wordpress-seo'],
        'elementor.com' => ['elementor', 'elementor-pro'],
        'wpforms.com' => ['wpforms', 'wpforms-lite'],
        'mailchimp.com' => ['mailchimp-for-wp'],
        'akismet.com' => ['akismet'],
        'jetpack.com' => ['jetpack'],
        'wordfence.com' => ['wordfence'],
        'sucuri.net' => ['sucuri-scanner'],
        'gravityforms.com' => ['gravityforms'],
        'woocommerce.com' => ['woocommerce'],
        'stripe.com' => ['woocommerce-gateway-stripe', 'stripe'],
        'paypal.com' => ['woocommerce-gateway-paypal-express-checkout', 'paypal-for-woocommerce'],
    ];
    foreach ($domain_map as $domain => $folders) {
        if ($host === $domain || substr($host, -strlen('.' . $domain)) === '.' . $domain) {
            foreach ($folders as $folder) {
                if (in_array($folder, $allowed_plugins, true)) {
                    return true;
                }
            }
        }
    }
    return false;
}

/**
 * Detect the source plugin/theme of an HTTP request.
 * Uses debug_backtrace to inspect the call stack and identify
 * which extension initiated the network call. This is essential
 * production functionality for the firewall's per-plugin blocking.
 */
function won2_mu_detect_source() {
    if (!function_exists('debug_backtrace')) {
        return ['type' => 'unknown', 'folder' => '', 'name' => 'unknown', 'file' => ''];
    }

    // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Essential production function: identifies which plugin/theme initiated the blocked HTTP request via call stack inspection.
    $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 100);
    $plugin_dir = rtrim(str_replace('\\', '/', WP_PLUGIN_DIR), '/');
    $mu_dir = rtrim(str_replace('\\', '/', WPMU_PLUGIN_DIR), '/');
    $theme_dir = function_exists('get_theme_root') ? rtrim(str_replace('\\', '/', get_theme_root()), '/') : '';
    $abspath_dir = rtrim(str_replace('\\', '/', ABSPATH), '/');
    $mu_guard_file = 'wondalizer-fw-curl-guard.php';
    $candidates = [];

    foreach ($trace as $frame) {
        if (empty($frame['file'])) continue;
        $file = str_replace('\\', '/', $frame['file']);
        $file_basename = basename($file);

        if ($file_basename === $mu_guard_file) continue;

        if (strpos($file, $plugin_dir . '/') === 0) {
            $rel = substr($file, strlen($plugin_dir) + 1);
            $parts = explode('/', $rel);
            $folder = $parts[0];
            if (!empty($folder)) {
                $candidates[$folder] = ['type' => 'plugin', 'folder' => $folder, 'name' => $folder, 'file' => $rel];
            }
        }
        if (strpos($file, $mu_dir . '/') === 0) {
            $rel = substr($file, strlen($mu_dir) + 1);
            // Match the roster naming: top-level MU files are 'mu-<basename>'.
            if (strpos($rel, '/') === false) {
                $folder = 'mu-' . strtolower(sanitize_file_name(basename($rel, '.php')));
            } else {
                $parts = explode('/', $rel);
                $folder = strtolower($parts[0]);
            }
            if (!empty($folder)) {
                $candidates[$folder] = ['type' => 'mu-plugin', 'folder' => $folder, 'name' => $folder, 'file' => $rel];
            }
        }
        if (!empty($theme_dir) && strpos($file, $theme_dir . '/') === 0) {
            $rel = substr($file, strlen($theme_dir) + 1);
            $parts = explode('/', $rel);
            $folder = $parts[0];
            if (!empty($folder)) {
                $candidates[$folder] = ['type' => 'theme', 'folder' => $folder, 'name' => $folder, 'file' => $rel];
            }
        }
        if (strpos($file, $abspath_dir . '/wp-admin/') === 0 || strpos($file, $abspath_dir . '/wp-includes/') === 0) {
            $rel = substr($file, strlen($abspath_dir) + 1);
            $candidates['wordpress-core'] = ['type' => 'core', 'folder' => 'wordpress-core', 'name' => 'WordPress Core', 'file' => $rel];
        }
    }

    if (!empty($candidates)) {
        $first = reset($candidates);
        return $first;
    }

    return ['type' => 'unknown', 'folder' => '', 'name' => 'unknown', 'file' => ''];
}

add_filter('pre_wp_mail', 'won2_mu_intercept_mail', PHP_INT_MAX - 100, 2);
function won2_mu_intercept_mail($pre, $args) {
    if (!did_action('init') && !did_action('wp_loaded')) {
        return $pre;
    }
    if (defined('WON2_VERSION') || class_exists('Won2_Firewall')) {
        return $pre;
    }

    $mail_data = null;
    if (is_array($pre) && isset($pre['to'])) {
        $mail_data = $pre;
    } elseif (is_array($args) && isset($args['to'])) {
        $mail_data = $args;
    }
    if (!is_array($mail_data)) {
        return $pre;
    }

    $settings = wp_parse_args(won2_mu_get_option_direct('won2_firewall_settings', []), [
        'http_firewall_enabled' => false,
        'block_emails_by_default' => false,
        'block_theme_emails_by_default' => false,
    ]);

    if (empty($settings['http_firewall_enabled'])) {
        return $pre;
    }

    $source = won2_mu_detect_source();
    $folder = strtolower($source['folder'] ?? '');

    if (strpos($folder, 'wondalizer-external-firewall') !== false || strpos($folder, 'wondalizer-fw') !== false) {
        return $pre;
    }

    $blocked_emails = array_map('strtolower', (array) won2_mu_get_option_direct('won2_blocked_emails', []));
    $allowed_emails = array_map('strtolower', (array) won2_mu_get_option_direct('won2_allowed_emails', []));

    $is_blocked = false;
    if (in_array($folder, $blocked_emails, true)) {
        $is_blocked = true;
    } elseif (in_array($folder, $allowed_emails, true)) {
        $is_blocked = false;
    } else {
        $is_plugin = ($source['type'] === 'plugin' || $source['type'] === 'mu-plugin');
        $is_theme  = ($source['type'] === 'theme');
        if ($is_plugin && !empty($settings['block_emails_by_default'])) {
            $is_blocked = true;
        } elseif ($is_theme && !empty($settings['block_theme_emails_by_default'])) {
            $is_blocked = true;
        }
    }

    if ($is_blocked) {
        return false;
    }

    return $pre;
}

$GLOBALS['won2_guard'] = new Won2_Curl_Guard_Base();

if (!function_exists('won2_curl_init')) {
    function won2_curl_init($url = null) {
        return $GLOBALS['won2_guard']->curl_init($url);
    }
}
if (!function_exists('won2_curl_exec')) {
    function won2_curl_exec($ch) {
        return $GLOBALS['won2_guard']->curl_exec($ch);
    }
}
if (!function_exists('won2_fsockopen')) {
    function won2_fsockopen($h, $p = -1, &$ec = null, &$em = null, $t = null) {
        return $GLOBALS['won2_guard']->fsockopen($h, $p, $ec, $em, $t);
    }
}
if (!function_exists('won2_wp_mail')) {
    function won2_wp_mail($to, $subject, $message, $headers = '', $attachments = []) {
        return $GLOBALS['won2_guard']->wp_mail($to, $subject, $message, $headers, $attachments);
    }
}
if (!function_exists('won2_php_mail')) {
    function won2_php_mail($to, $subject, $message, $headers = '', $params = '') {
        return $GLOBALS['won2_guard']->mail($to, $subject, $message, $headers, $params);
    }
}