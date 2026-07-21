<?php
/**
 * Wondalizer External Firewall — Guard (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Guard')) {
class Won2_Guard {
    private static $instance = null;
    private static $blocked_plugins = null;
    private static $allowed_plugins = null;
    private static $blocked_obs = null;
    private static $blacklist = null;
    private static $whitelist = null;
    private static $core_hosts = null;
    private static $settings = null;
    private static $plugin_allowed_domains = null;

    public static function init() {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        // Register immediately — by the time this class loads, muplugins_loaded
        // has already fired, so hooking it would never run.
        $this->early_intercept();
    }

    private static function get_option_direct($option, $default = []) {
        if (class_exists('Won2_Admin_Actions') && method_exists('Won2_Admin_Actions', 'get_option_direct')) {
            return Won2_Admin_Actions::get_option_direct($option, $default);
        }
        return get_option($option, $default);
    }

    public function early_intercept() {
        if (!function_exists('get_transient')) return;
        $settings = self::get_option_direct('won2_firewall_settings', []);
        if (!is_array($settings)) $settings = [];
        if (!empty($settings['http_firewall_enabled'])) {
            add_filter('pre_http_request', [$this, 'guard_http'], PHP_INT_MAX - 200, 3);
        }
    }

    public static function clear_guard_cache() {
        self::$blocked_plugins = null;
        self::$allowed_plugins = null;
        self::$blocked_obs     = null;
        self::$blacklist       = null;
        self::$whitelist       = null;
        self::$settings        = null;
        self::$core_hosts      = null;
        self::$plugin_allowed_domains = null;
        wp_cache_delete('won2_blocked_plugins', 'options');
        wp_cache_delete('won2_allowed_plugins', 'options');
        wp_cache_delete('won2_blocked_obfuscation', 'options');
        wp_cache_delete('won1_blacklist_domains', 'options');
        wp_cache_delete('won1_whitelist_domains', 'options');
        wp_cache_delete('won2_firewall_settings', 'options');
        wp_cache_delete('alloptions', 'options');
        if (function_exists('wp_cache_flush')) wp_cache_flush();
    }

    /**
     * Match a traced folder against a block/allow list, accepting roster and
     * legacy naming variants ('name.php', 'mu-name', 'name').
     */
    private static function folder_matches($folder, $list) {
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

    public function guard_http($preempt, $parsed_args, $url) {
        // Another handler already short-circuited this request — respect it.
        if (false !== $preempt) {
            return $preempt;
        }

        $host = wp_parse_url($url, PHP_URL_HOST);
        $host = $host ? strtolower($host) : '';

        if (self::$settings === null) {
            self::$settings = wp_parse_args(self::get_option_direct('won2_firewall_settings', []), [
                'block_by_default' => false,
                'block_themes_by_default' => false,
                'whitelist_woocommerce' => false,
                'whitelist_edd' => false,
                'whitelist_paypal' => false,
                'hard_block_mode' => false,
                'allow_same_site_for_blocked' => true,
            ]);
        }

        $source = $this->detect_source();
        $folder = strtolower($source['folder'] ?? '');

        // Self-protection: this plugin is never blocked.
        if (strpos($folder, 'wondalizer-external-firewall') !== false || strpos($folder, 'wondalizer-fw') !== false) {
            return $preempt;
        }

        if (self::$blocked_plugins === null) {
            $blocked = (array) self::get_option_direct('won2_blocked_plugins', []);
            self::$blocked_plugins = array_map('strtolower', $blocked);
        }
        if (self::$allowed_plugins === null) {
            $allowed = (array) self::get_option_direct('won2_allowed_plugins', []);
            self::$allowed_plugins = array_map('strtolower', $allowed);
        }
        if (self::$blocked_obs === null) {
            $blocked = (array) self::get_option_direct('won2_blocked_obfuscation', []);
            self::$blocked_obs = array_map('strtolower', $blocked);
        }

        $site_host = wp_parse_url(home_url(), PHP_URL_HOST);
        $is_same_site = ($host === $site_host);

        // Hard Block Mode: default-deny for everything not explicitly allowed.
        if (!empty(self::$settings['hard_block_mode'])) {
            $src_type = $source['type'] ?? 'unknown';
            $is_core_source = ($src_type === 'core' || $folder === 'wordpress-core' || $folder === 'wp-core');
            if (!$is_core_source && !self::folder_matches($folder, self::$allowed_plugins)
                && !($is_same_site && !empty(self::$settings['allow_same_site_for_blocked']))) {
                $is_whitelisted_commerce = false;
                if (!empty(self::$settings['whitelist_woocommerce']) && strpos($folder, 'woocommerce') !== false) {
                    $is_whitelisted_commerce = true;
                }
                if (!empty(self::$settings['whitelist_edd']) && (strpos($folder, 'easy-digital-downloads') !== false || strpos($folder, 'edd') !== false)) {
                    $is_whitelisted_commerce = true;
                }
                if (!empty(self::$settings['whitelist_paypal']) && strpos($folder, 'paypal') !== false) {
                    $is_whitelisted_commerce = true;
                }
                if (!$is_whitelisted_commerce) {
                    if (class_exists('Won2_Logger')) {
                        Won2_Logger::init()->log('http', $url, $host, 'BLOCKED', 'hard_block', $source, true);
                        Won2_Logger::init()->flush();
                    }
                    return new WP_Error('won1_blocked', esc_html__('Request blocked by Wondalizer External Firewall (Hard Block Mode).', 'wondalizer-external-firewall'));
                }
            }
        }

        // Determine block status FIRST — an explicit block must win over
        // core-host allows and the domain whitelist (strict mode).
        $is_blocked = false;
        if (self::folder_matches($folder, self::$blocked_plugins) || self::folder_matches($folder, self::$blocked_obs)) {
            $is_blocked = true;
        } elseif (self::folder_matches($folder, self::$allowed_plugins)) {
            $is_blocked = false;
        } else {
            $is_plugin = ($source['type'] === 'plugin' || $source['type'] === 'mu-plugin');
            $is_theme  = ($source['type'] === 'theme');
            if ($is_plugin && !empty(self::$settings['block_by_default'])) {
                $is_blocked = true;
            } elseif ($is_theme && !empty(self::$settings['block_themes_by_default'])) {
                $is_blocked = true;
            }
        }

        if ($is_blocked) {
            // Core sources stay governable by the whitelist and the same-site
            // exception: whitelisting api.wordpress.org unblocks it for core.
            $src_is_core = ($source['type'] ?? '') === 'core' || in_array($folder, ['wordpress-core', 'wp-core', 'core'], true);
            if ($src_is_core) {
                if (self::$whitelist === null) {
                    self::$whitelist = self::get_option_direct('won1_whitelist_domains', []);
                    if (!is_array(self::$whitelist)) self::$whitelist = [];
                    self::$whitelist = array_filter(array_map(function($d) {
                        $d = strtolower(trim($d));
                        $d = preg_replace('#^https?://#', '', $d);
                        return rtrim($d, '/');
                    }, self::$whitelist));
                }
                foreach (self::$whitelist as $w) {
                    if ($w !== '' && ($host === $w || substr($host, -strlen('.'.$w)) === '.'.$w)) {
                        return $preempt;
                    }
                }
                if ($is_same_site && !empty(self::$settings['allow_same_site_for_blocked'])) {
                    return $preempt;
                }
            }
            $is_whitelisted_commerce = false;
            if (!empty(self::$settings['whitelist_woocommerce']) && strpos($folder, 'woocommerce') !== false) {
                $is_whitelisted_commerce = true;
            }
            if (!empty(self::$settings['whitelist_edd']) && (strpos($folder, 'easy-digital-downloads') !== false || strpos($folder, 'edd') !== false)) {
                $is_whitelisted_commerce = true;
            }
            if (!empty(self::$settings['whitelist_paypal']) && strpos($folder, 'paypal') !== false) {
                $is_whitelisted_commerce = true;
            }
            if (!$is_whitelisted_commerce) {
                // Per-plugin explicit domain exceptions (set via the Domains modal).
                if (self::$plugin_allowed_domains === null) {
                    $pad = self::get_option_direct('won2_plugin_allowed_domains', []);
                    self::$plugin_allowed_domains = is_array($pad) ? $pad : [];
                }
                $allowed_for_this_plugin = self::$plugin_allowed_domains[$folder] ?? [];
                foreach ((array) $allowed_for_this_plugin as $ad) {
                    $ad = strtolower(trim((string) $ad));
                    if ($ad !== '' && ($host === $ad || substr($host, -strlen('.'.$ad)) === '.'.$ad)) {
                        return $preempt;
                    }
                }
                // Global allowed-domain exceptions for blocked plugins.
                if (!empty(self::$settings['allowed_domains']) && is_array(self::$settings['allowed_domains'])) {
                    foreach (self::$settings['allowed_domains'] as $ad) {
                        $ad = strtolower(trim($ad));
                        if ($ad !== '' && ($host === $ad || substr($host, -strlen('.'.$ad)) === '.'.$ad)) {
                            return $preempt;
                        }
                    }
                }
                // Same-site exception: blocked plugins may still reach this
                // site itself (loopback, cron, REST) when the setting is on.
                if ($is_same_site && !empty(self::$settings['allow_same_site_for_blocked'])) {
                    return $preempt;
                }
                if (class_exists('Won2_Logger')) {
                    Won2_Logger::init()->log('http', $url, $host, 'BLOCKED', 'plugin_blocklist', $source, true);
                    Won2_Logger::init()->flush();
                }
                return new WP_Error('won1_blocked', esc_html__('Request blocked by Wondalizer External Firewall.', 'wondalizer-external-firewall'));
            }
        }

        // Domain blocklist beats the whitelist (strict mode).
        if (self::$blacklist === null) {
            self::$blacklist = self::get_option_direct('won1_blacklist_domains', []);
            if (!is_array(self::$blacklist)) self::$blacklist = [];
        }
        foreach (self::$blacklist as $b) {
            if ($host === $b || substr($host, -strlen('.'.$b)) === '.'.$b) {
                if (class_exists('Won2_Logger')) {
                    Won2_Logger::init()->log('http', $url, $host, 'BLOCKED', 'blacklist', $source, true);
                    Won2_Logger::init()->flush();
                }
                return new WP_Error('won1_blocked', esc_html__('Request blocked by Wondalizer External Firewall.', 'wondalizer-external-firewall'));
            }
        }

        if (self::$core_hosts === null) {
            self::$core_hosts = ['wordpress.org', 'api.wordpress.org', 'downloads.wordpress.org', 'planet.wordpress.org', 'ps.w.org', 's.w.org'];
        }
        foreach (self::$core_hosts as $ch) {
            if ($host === $ch || substr($host, -strlen('.'.$ch)) === '.'.$ch) return $preempt;
        }

        if (self::$whitelist === null) {
            self::$whitelist = self::get_option_direct('won1_whitelist_domains', []);
            if (!is_array(self::$whitelist)) self::$whitelist = [];
        }
        foreach (self::$whitelist as $w) {
            if ($host === $w || substr($host, -strlen('.'.$w)) === '.'.$w) return $preempt;
        }

        return $preempt;
    }

    private function detect_source() {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 30);
        $plugin_dir = str_replace('\\', '/', WP_PLUGIN_DIR);
        $mu_dir = str_replace('\\', '/', WPMU_PLUGIN_DIR);
        $theme_dir = str_replace('\\', '/', get_theme_root());
        $fw_dir = str_replace('\\', '/', WON2_DIR);

        foreach ($trace as $frame) {
            if (empty($frame['file'])) continue;
            $file = str_replace('\\', '/', $frame['file']);
            $file_basename = basename($file);

            if (strpos($file, $fw_dir) === 0) continue;

            if ($file_basename === 'wondalizer-fw-curl-guard.php') continue;

            if (strpos($file, $plugin_dir) === 0) {
                $rel = substr($file, strlen($plugin_dir) + 1);
                $parts = explode('/', $rel);
                return ['type' => 'plugin', 'folder' => $parts[0], 'name' => $parts[0], 'file' => $rel];
            }
            if (strpos($file, $mu_dir) === 0) {
                $rel = substr($file, strlen($mu_dir) + 1);
                $parts = explode('/', $rel);
                return ['type' => 'mu-plugin', 'folder' => $parts[0], 'name' => $parts[0], 'file' => $rel];
            }
            if (strpos($file, $theme_dir) === 0) {
                $rel = substr($file, strlen($theme_dir) + 1);
                $parts = explode('/', $rel);
                return ['type' => 'theme', 'folder' => $parts[0], 'name' => $parts[0], 'file' => $rel];
            }
        }
        return ['type' => 'unknown', 'folder' => '', 'name' => 'unknown', 'file' => ''];
    }
}
}

if (!is_admin()) {
    Won2_Guard::init();
}