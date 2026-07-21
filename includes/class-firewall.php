<?php
/**
 * Wondalizer External Firewall — Firewall Engine (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Firewall')) {
class Won2_Firewall {
    private static $instance = null;
    private static $settings = null;
    private static $whitelist = null;
    private static $blacklist = null;
    private static $core_hosts = null;
    private static $blocked_plugins = null;
    private static $allowed_plugins = null;
    private static $blocked_emails = null;
    private static $allowed_emails = null;
    private static $blocked_obs = null;
    private static $plugin_allowed_domains = null;
    private static $allowed_domains = null;

    public static function init() {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        $this->load_settings();
    }

    private static function get_option_direct($option, $default = array()) {
        wp_cache_delete($option, 'options');
        wp_cache_delete('alloptions', 'options');
        wp_cache_delete('notoptions', 'options');
        global $wpdb;
        if (isset($wpdb) && $wpdb instanceof wpdb) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- intentional direct DB for cache bypass
            $row = $wpdb->get_row($wpdb->prepare(
                "SELECT option_value FROM $wpdb->options WHERE option_name = %s LIMIT 1",
                $option
            ));
            if ($row) {
                $val = maybe_unserialize($row->option_value);
                if (is_array($default) && !is_array($val)) {
                    $val = array();
                }
                return $val;
            }
            return $default;
        }
        $val = get_option($option, $default);
        if (is_array($default) && !is_array($val)) {
            $val = array();
        }
        return $val;
    }

    private static function get_option_array($option) {
        $val = self::get_option_direct($option, array());
        if (!is_array($val)) $val = array();
        return array_map('strtolower', $val);
    }

    private function load_settings() {
        if (self::$settings === null) {
            self::$settings = wp_parse_args(self::get_option_direct('won2_firewall_settings', []), [
                'http_firewall_enabled' => false,
                'hard_block_mode' => false,
                'cron_firewall_enabled' => false,
                'logging_enabled' => true,
                'log_http_blocked' => true,
                'log_http_allowed' => false,
                'log_email_blocked' => true,
                'log_email_allowed' => true,
                'log_internal_http' => false,
                'curl_cache_enabled' => false,
                'block_recaptcha' => false,
                'cron_block_by_default' => false,
                'block_by_default' => false,
                'block_emails_by_default' => false,
                'block_themes_by_default' => false,
                'block_theme_emails_by_default' => false,
                'whitelist_woocommerce' => false,
                'whitelist_edd' => false,
                'whitelist_paypal' => false,
                'allow_same_site_for_blocked' => true,
                'allowed_domains' => array(),
            ]);
        }
    }

    public static function get_settings() {
        self::init()->load_settings();
        return self::$settings;
    }

    public static function refresh_settings() {
        self::$settings = null;
        self::$whitelist = null;
        self::$blacklist = null;
        self::$blocked_plugins = null;
        self::$allowed_plugins = null;
        self::$blocked_emails = null;
        self::$allowed_emails = null;
        self::$blocked_obs = null;
        self::$plugin_allowed_domains = null;
        self::$allowed_domains = null;
        $keys = array(
            'won2_firewall_settings',
            'won2_blocked_plugins',
            'won2_allowed_plugins',
            'won2_blocked_emails',
            'won2_allowed_emails',
            'won2_blocked_obfuscation',
            'won2_rewritten_plugins',
            'won2_plugin_allowed_domains',
            'won1_whitelist_domains',
            'won1_blacklist_domains',
            'won2_blocked_cron_hooks',
            'won2_allowed_cron_hooks',
        );
        foreach ($keys as $k) {
            wp_cache_delete($k, 'options');
        }
        wp_cache_delete('alloptions', 'options');
        wp_cache_delete('notoptions', 'options');
        if (class_exists('Won2_Guard')) {
            Won2_Guard::clear_guard_cache();
        }
        if (function_exists('wp_cache_flush')) {
            wp_cache_flush();
        }
        delete_transient('won1_roster_v3');
        delete_transient('won1_roster_v3_partial');
        delete_transient('won1_roster_incomplete');
        wp_cache_delete('won1_roster_v3', 'transient');
        wp_cache_delete('won1_roster_v3_partial', 'transient');
        wp_cache_delete('won1_roster_incomplete', 'transient');
    }

    public static function clear_block_caches() {
        self::refresh_settings();
    }

    public function start_interception() {
        add_filter('pre_http_request', [$this, 'intercept_http'], PHP_INT_MAX - 100, 3);
        add_filter('pre_wp_mail', [$this, 'intercept_mail'], PHP_INT_MAX - 100, 2);
        add_filter('wp_mail', [$this, 'intercept_mail_content'], PHP_INT_MAX - 100, 1);
        add_filter('cron_schedules', [$this, 'intercept_cron_schedules'], PHP_INT_MAX - 100, 1);
        add_action('init', [$this, 'intercept_cron_hooks'], 1);
    }

    /**
     * Match a traced folder against a block/allow list, accepting the naming
     * variants used by the roster and older versions:
     * 'name.php' (single-file plugins), 'mu-name' (roster MU naming) and
     * 'name' (plain folder). Prevents blocked plugins slipping through due
     * to naming mismatches.
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
        // WordPress core has been listed under several names across versions —
        // treat them all as the same entity for block/allow/unblock.
        $core_aliases = self::core_folder_aliases();
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

    /**
     * All folder names that mean "WordPress core" across versions.
     */
    public static function core_folder_aliases() {
        return ['wordpress-core', 'wp-core', 'core', 'wp-admin', 'wp-includes'];
    }

    private function is_commerce_whitelisted($folder, $settings) {
        if (!empty($settings['whitelist_woocommerce']) && strpos($folder, 'woocommerce') !== false) {
            return true;
        }
        if (!empty($settings['whitelist_edd']) && (strpos($folder, 'easy-digital-downloads') !== false || strpos($folder, 'edd') !== false)) {
            return true;
        }
        if (!empty($settings['whitelist_paypal']) && strpos($folder, 'paypal') !== false) {
            return true;
        }
        return false;
    }

    /**
     * Final enforcement net: before any ALLOWED verdict is logged for a
     * non-exception reason, re-verify the source against the block lists.
     * If it is explicitly blocked, the verdict flips to BLOCKED — the log
     * and the block list can never disagree.
     *
     * Intentional exceptions (self-protection, per-plugin domain exceptions,
     * global allowed domains, same-site exception) do NOT call this helper.
     */
    private function enforce_not_blocked($url, $host, $source, $settings) {
        $folder = strtolower($source['folder'] ?? '');
        if ($folder === '' || $folder === 'unknown') {
            return null;
        }
        $blocked_plugins = $this->get_blocked_plugins();
        $blocked_obs = $this->get_blocked_obs();
        if (!self::folder_matches($folder, $blocked_plugins) && !self::folder_matches($folder, $blocked_obs)) {
            return null;
        }
        if ($this->is_commerce_whitelisted($folder, $settings)) {
            return null;
        }
        $this->log_http($url, $host, 'BLOCKED', 'block_enforcement', $source);
        return new WP_Error('won1_blocked', esc_html__('Request blocked by Wondalizer External Firewall.', 'wondalizer-external-firewall'));
    }

    public function intercept_http($preempt, $parsed_args, $url) {
        // Another handler already short-circuited this request — respect it.
        if (false !== $preempt) {
            return $preempt;
        }

        $this->load_settings();
        $settings = self::$settings;

        if (empty($settings['http_firewall_enabled'])) {
            return $preempt;
        }

        $host = wp_parse_url($url, PHP_URL_HOST);
        $host = $host ? strtolower($host) : '';

        $source = class_exists('Won2_Source') ? Won2_Source::init()->trace_for_firewall() : ['folder' => '', 'type' => 'unknown'];
        $folder = strtolower($source['folder'] ?? '');

        if (empty($folder)) {
            $folder = 'unknown';
            $source['folder'] = 'unknown';
            $source['type'] = 'unknown';
        }

        // Self-protection: this plugin is never blocked.
        if (strpos($folder, 'wondalizer-external-firewall') !== false || strpos($folder, 'wondalizer-fw') !== false) {
            $this->log_http($url, $host, 'ALLOWED', 'self_protection', $source);
            return $preempt;
        }

        $blocked_plugins = $this->get_blocked_plugins();
        $allowed_plugins = $this->get_allowed_plugins();
        $blocked_obs = $this->get_blocked_obs();

        // Hard Block Mode: default-deny. Every plugin, theme, drop-in or
        // unknown source that is NOT explicitly on the Allowed list is
        // blocked — this also covers unknown or hijacked sources that never
        // appear on the roster. The only way to allow a plugin in this mode
        // is to mark it Allowed on the HTTP Firewall page.
        if (!empty($settings['hard_block_mode'])) {
            $src_type = $source['type'] ?? 'unknown';
            $is_core_source = ($src_type === 'core' || $folder === 'wordpress-core' || $folder === 'wp-core');
            $site_host_hb = wp_parse_url(home_url(), PHP_URL_HOST);
            if (!$is_core_source && !self::folder_matches($folder, $allowed_plugins) && !$this->is_commerce_whitelisted($folder, $settings)
                && !($host === $site_host_hb && !empty($settings['allow_same_site_for_blocked']))) {
                $this->log_http($url, $host, 'BLOCKED', 'hard_block', $source);
                return new WP_Error('won1_blocked', esc_html__('Request blocked by Wondalizer External Firewall (Hard Block Mode).', 'wondalizer-external-firewall'));
            }
        }

        // Determine block status FIRST — an explicit block must win over
        // whitelists and allowed-domain lists, otherwise blocked plugins
        // leak requests and get logged as ALLOWED (strict mode).
        $is_blocked = false;
        if (self::folder_matches($folder, $blocked_plugins) || self::folder_matches($folder, $blocked_obs)) {
            $is_blocked = true;
        } elseif (!self::folder_matches($folder, $allowed_plugins)) {
            $is_plugin = ($source['type'] === 'plugin' || $source['type'] === 'mu-plugin');
            $is_theme = ($source['type'] === 'theme');
            if ($is_plugin && !empty($settings['block_by_default'])) {
                $is_blocked = true;
            } elseif ($is_theme && !empty($settings['block_themes_by_default'])) {
                $is_blocked = true;
            }
        }

        if ($is_blocked) {
            // WordPress core is blockable like any other extension, but keeps
            // host-level exemptions: per-source domain exceptions, global
            // allowed domains, the domain whitelist and the same-site
            // exception still apply, so e.g. whitelisting api.wordpress.org
            // unblocks it for core requests while the rest of core stays blocked.
            $is_core_source = in_array($folder, self::core_folder_aliases(), true);
            if ($is_core_source) {
                $plugin_allowed_domains = $this->get_plugin_allowed_domains();
                foreach (($plugin_allowed_domains[$folder] ?? []) as $ad) {
                    if ($host === $ad || substr($host, -strlen('.'.$ad)) === '.'.$ad) {
                        $this->log_http($url, $host, 'ALLOWED', 'plugin_domain_whitelist', $source);
                        return $preempt;
                    }
                }
                foreach ($this->get_allowed_domains() as $ad) {
                    if ($host === $ad || substr($host, -strlen('.'.$ad)) === '.'.$ad) {
                        $this->log_http($url, $host, 'ALLOWED', 'global_allowed_domain', $source);
                        return $preempt;
                    }
                }
                if ($this->is_whitelisted($host)) {
                    $this->log_http($url, $host, 'ALLOWED', 'whitelist', $source);
                    return $preempt;
                }
                $site_host_core = wp_parse_url(home_url(), PHP_URL_HOST);
                if ($host === $site_host_core && !empty($settings['allow_same_site_for_blocked'])) {
                    $this->log_http($url, $host, 'ALLOWED', 'same_site_exception', $source);
                    return $preempt;
                }
                $this->log_http($url, $host, 'BLOCKED', 'core_blocked', $source);
                return new WP_Error('won1_blocked', esc_html__('Request blocked by Wondalizer External Firewall.', 'wondalizer-external-firewall'));
            }

            if (!$this->is_commerce_whitelisted($folder, $settings)) {
                // Per-plugin explicit domain exceptions (set via the Domains modal).
                $plugin_allowed_domains = $this->get_plugin_allowed_domains();
                $allowed_for_this_plugin = $plugin_allowed_domains[$folder] ?? [];
                foreach ($allowed_for_this_plugin as $ad) {
                    if ($host === $ad || substr($host, -strlen('.'.$ad)) === '.'.$ad) {
                        $this->log_http($url, $host, 'ALLOWED', 'plugin_domain_whitelist', $source);
                        return $preempt;
                    }
                }

                // Global allowed-domain exceptions for blocked plugins.
                $global_allowed = $this->get_allowed_domains();
                foreach ($global_allowed as $ad) {
                    if ($host === $ad || substr($host, -strlen('.'.$ad)) === '.'.$ad) {
                        $this->log_http($url, $host, 'ALLOWED', 'global_allowed_domain', $source);
                        return $preempt;
                    }
                }

                $site_host = wp_parse_url(home_url(), PHP_URL_HOST);
                if ($host === $site_host && !empty($settings['allow_same_site_for_blocked'])) {
                    $this->log_http($url, $host, 'ALLOWED', 'same_site_exception', $source);
                    return $preempt;
                }

                $this->log_http($url, $host, 'BLOCKED', 'plugin_blocklist', $source);
                return new WP_Error('won1_blocked', esc_html__('Request blocked by Wondalizer External Firewall.', 'wondalizer-external-firewall'));
            }
        }

        // Domain blocklist beats the whitelist (strict mode).
        if ($this->is_blacklisted($host)) {
            $this->log_http($url, $host, 'BLOCKED', 'blacklist', $source);
            return new WP_Error('won1_blocked', esc_html__('Request blocked by Wondalizer External Firewall.', 'wondalizer-external-firewall'));
        }

        if ($this->is_whitelisted($host)) {
            $enforced = $this->enforce_not_blocked($url, $host, $source, $settings);
            if ($enforced) return $enforced;
            $this->log_http($url, $host, 'ALLOWED', 'whitelist', $source);
            return $preempt;
        }

        if ($this->is_core_host($host)) {
            $enforced = $this->enforce_not_blocked($url, $host, $source, $settings);
            if ($enforced) return $enforced;
            $this->log_http($url, $host, 'ALLOWED', 'core', $source);
            return $preempt;
        }

        $is_domain_fallback_allowed = $this->is_domain_fallback_allowed($host, $allowed_plugins);
        if ($is_domain_fallback_allowed) {
            $enforced = $this->enforce_not_blocked($url, $host, $source, $settings);
            if ($enforced) return $enforced;
            $this->log_http($url, $host, 'ALLOWED', 'domain_fallback', $source);
            return $preempt;
        }

        $site_host = wp_parse_url(home_url(), PHP_URL_HOST);
        $is_same_site = ($host === $site_host);
        if ($is_same_site && empty($settings['log_internal_http'])) {
            return $preempt;
        }

        $enforced = $this->enforce_not_blocked($url, $host, $source, $settings);
        if ($enforced) return $enforced;
        $this->log_http($url, $host, 'ALLOWED', 'default', $source);
        return $preempt;
    }


    public function intercept_mail($pre, $args) {
        $this->load_settings();
        $settings = self::$settings;
        if (empty($settings['http_firewall_enabled'])) return $pre;
        if (is_array($pre) && $args === null) {
            $args = $pre;
            $pre  = null;
        }
        if (is_string($args)) {
            $args = array('to' => $args, 'subject' => '', 'message' => '', 'headers' => '', 'attachments' => array());
        }
        if (!is_array($args)) {
            return $pre;
        }
        // Another handler already short-circuited this email — respect it.
        if (null !== $pre) {
            return $pre;
        }
        $source = class_exists('Won2_Source') ? Won2_Source::init()->trace_for_firewall() : array('folder' => '', 'type' => 'unknown');
        $folder = strtolower($source['folder'] ?? '');
        if (strpos($folder, 'wondalizer-external-firewall') !== false || strpos($folder, 'wondalizer-fw') !== false) {
            $this->log_email($args['to'] ?? '', 'ALLOWED', 'self_protection', $source);
            return $pre;
        }
        $blocked_emails = $this->get_blocked_emails();
        $allowed_emails = $this->get_allowed_emails();
        $is_blocked = false;
        if (self::folder_matches($folder, $blocked_emails)) {
            $is_blocked = true;
        } elseif (self::folder_matches($folder, $allowed_emails)) {
            $is_blocked = false;
        } else {
            $is_plugin = ($source['type'] === 'plugin' || $source['type'] === 'mu-plugin');
            $is_theme = ($source['type'] === 'theme');
            if ($is_plugin && !empty($settings['block_emails_by_default'])) {
                $is_blocked = true;
            } elseif ($is_theme && !empty($settings['block_theme_emails_by_default'])) {
                $is_blocked = true;
            }
        }
        $to = isset($args['to']) ? (is_array($args['to']) ? implode(',', $args['to']) : $args['to']) : '';
        if ($is_blocked) {
            $is_whitelisted_commerce = false;
            if (!empty($settings['whitelist_woocommerce']) && strpos($folder, 'woocommerce') !== false) {
                $is_whitelisted_commerce = true;
            }
            if (!empty($settings['whitelist_edd']) && (strpos($folder, 'easy-digital-downloads') !== false || strpos($folder, 'edd') !== false)) {
                $is_whitelisted_commerce = true;
            }
            if (!empty($settings['whitelist_paypal']) && strpos($folder, 'paypal') !== false) {
                $is_whitelisted_commerce = true;
            }
            if (!$is_whitelisted_commerce) {
                $this->log_email($to, 'BLOCKED', 'email_blocklist', $source);
                return false;
            }
        }
        $this->log_email($to, 'ALLOWED', 'default', $source);
        return $pre;
    }

    public function intercept_mail_content($atts) {
        $this->load_settings();
        $settings = self::$settings;
        if (empty($settings['http_firewall_enabled'])) return $atts;
        return $atts;
    }

    public function intercept_cron_schedules($schedules) {
        $this->load_settings();
        $settings = self::$settings;
        if (empty($settings['cron_firewall_enabled'])) return $schedules;
        if (!empty($settings['cron_block_by_default'])) {
            $allowed = self::get_option_array('won2_allowed_cron_hooks');
            $core = array('hourly', 'twicedaily', 'daily', 'weekly');
            foreach ($schedules as $name => $schedule) {
                if (!in_array($name, $core, true) && !in_array($name, $allowed, true)) {
                    unset($schedules[$name]);
                }
            }
        }
        return $schedules;
    }

    public function intercept_cron_hooks() {
        $this->load_settings();
        $settings = self::$settings;
        if (empty($settings['cron_firewall_enabled'])) return;
        $blocked = self::get_option_array('won2_blocked_cron_hooks');
        if (empty($blocked)) return;
        add_filter('pre_option_cron', function($value) use ($blocked) {
            if (!is_array($value)) return $value;
            foreach ($blocked as $hook) {
                if (isset($value[$hook])) {
                    unset($value[$hook]);
                }
            }
            return $value;
        }, PHP_INT_MAX - 100);
        foreach ($blocked as $hook) {
            remove_all_actions($hook);
        }
    }

    private static function is_core_host($host) {
        if (self::$core_hosts === null) {
            self::$core_hosts = [
                'wordpress.org', 'api.wordpress.org', 'downloads.wordpress.org',
                'planet.wordpress.org', 'core.trac.wordpress.org', 'meta.trac.wordpress.org',
                'ps.w.org', 's.w.org', 'wordpress.com', 'jetpack.wordpress.com',
                'public-api.wordpress.com', 'stats.wordpress.com',
            ];
        }
        foreach (self::$core_hosts as $core) {
            if ($host === $core || substr($host, -strlen('.'.$core)) === '.'.$core) return true;
        }
        return false;
    }

    private static function is_whitelisted($host) {
        if (self::$whitelist === null) {
            $raw = self::get_option_direct('won1_whitelist_domains', []);
            if (!is_array($raw)) $raw = [];
            self::$whitelist = array_filter(array_map(function($d) {
                $d = strtolower(trim($d));
                $d = preg_replace('#^https?://#', '', $d);
                $d = rtrim($d, '/');
                return $d;
            }, $raw));
        }
        foreach (self::$whitelist as $w) {
            if ($host === $w || substr($host, -strlen('.'.$w)) === '.'.$w) return true;
        }
        return false;
    }

    private static function is_blacklisted($host) {
        if (self::$blacklist === null) {
            $raw = self::get_option_direct('won1_blacklist_domains', []);
            if (!is_array($raw)) $raw = [];
            self::$blacklist = array_filter(array_map(function($d) {
                $d = strtolower(trim($d));
                $d = preg_replace('#^https?://#', '', $d);
                $d = rtrim($d, '/');
                return $d;
            }, $raw));
        }
        foreach (self::$blacklist as $b) {
            if ($host === $b || substr($host, -strlen('.'.$b)) === '.'.$b) return true;
        }
        return false;
    }

    public static function is_url_blocked($url) {
        $host = wp_parse_url($url, PHP_URL_HOST);
        if (empty($host)) {
            return false;
        }
        $host = strtolower($host);
        if (self::is_whitelisted($host)) {
            return false;
        }
        if (self::is_blacklisted($host)) {
            return true;
        }
        if (self::is_core_host($host)) {
            return false;
        }
        return false;
    }

    private function get_allowed_domains() {
        if (self::$allowed_domains === null) {
            $settings = self::get_settings();
            $ad = $settings['allowed_domains'] ?? array();
            if (!is_array($ad)) $ad = array();
            self::$allowed_domains = array_map('strtolower', $ad);
        }
        return self::$allowed_domains;
    }

    private function get_blocked_plugins() {
        if (self::$blocked_plugins === null) {
            self::$blocked_plugins = self::get_option_array('won2_blocked_plugins');
        }
        return self::$blocked_plugins;
    }

    private function get_allowed_plugins() {
        if (self::$allowed_plugins === null) {
            self::$allowed_plugins = self::get_option_array('won2_allowed_plugins');
        }
        return self::$allowed_plugins;
    }

    private function get_blocked_emails() {
        if (self::$blocked_emails === null) {
            self::$blocked_emails = self::get_option_array('won2_blocked_emails');
        }
        return self::$blocked_emails;
    }

    private function get_allowed_emails() {
        if (self::$allowed_emails === null) {
            self::$allowed_emails = self::get_option_array('won2_allowed_emails');
        }
        return self::$allowed_emails;
    }

    private function get_blocked_obs() {
        if (self::$blocked_obs === null) {
            self::$blocked_obs = self::get_option_array('won2_blocked_obfuscation');
        }
        return self::$blocked_obs;
    }

    private function get_plugin_allowed_domains() {
        if (self::$plugin_allowed_domains === null) {
            $val = self::get_option_direct('won2_plugin_allowed_domains', array());
            if (!is_array($val)) $val = array();
            // Normalize entries saved before save-time normalization existed.
            foreach ($val as $k => $list) {
                if (!is_array($list)) { unset($val[$k]); continue; }
                $val[$k] = array_values(array_filter(array_map(function($d) {
                    $d = strtolower(trim((string) $d));
                    $d = preg_replace('#^https?://#', '', $d);
                    return rtrim($d, '/');
                }, $list)));
            }
            self::$plugin_allowed_domains = $val;
        }
        return self::$plugin_allowed_domains;
    }

    private function is_domain_fallback_allowed($host, $allowed_plugins) {
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

    private function log_http($url, $host, $status, $reason, $source = null) {
        $settings = self::$settings;
        if (empty($settings['logging_enabled'])) return;
        if ($status === 'BLOCKED' && empty($settings['log_http_blocked'])) return;
        if ($status === 'ALLOWED' && empty($settings['log_http_allowed'])) return;

        $is_same = ($host === wp_parse_url(home_url(), PHP_URL_HOST));
        if ($is_same && empty($settings['log_internal_http'])) return;

        $this->buffer_log([
            'type' => 'http', 'url' => $url, 'host' => $host,
            'status' => $status, 'reason' => $reason, 'time' => time(), 'same_site' => $is_same,
        ], $source);
    }

    private function log_email($to, $status, $reason, $source = null) {
        $settings = self::$settings;
        if (empty($settings['logging_enabled'])) return;
        if ($status === 'BLOCKED' && empty($settings['log_email_blocked'])) return;
        if ($status === 'ALLOWED' && empty($settings['log_email_allowed'])) return;

        $this->buffer_log([
            'type' => 'email', 'to' => $to,
            'status' => $status, 'reason' => $reason, 'time' => time(),
        ], $source);
    }

    private function buffer_log($entry, $source = null) {
        global $won2_intercept_buffer;
        if (!is_array($won2_intercept_buffer)) $won2_intercept_buffer = [];
        $won2_intercept_buffer[] = $entry;

        if (class_exists('Won2_Logger')) {
            if ($source === null && class_exists('Won2_Source')) {
                $source = Won2_Source::init()->trace_for_firewall();
            }
            if ($source === null) {
                $source = ['type'=>'unknown','name'=>'unknown','folder'=>'','file'=>''];
            }
            $type = $entry['type'] ?? 'http';
            $url = $entry['url'] ?? ($entry['to'] ?? '');
            $host = $entry['host'] ?? '';
            $status = $entry['status'] ?? 'ALLOWED';
            $reason = $entry['reason'] ?? '';
            $blocked = ($status === 'BLOCKED');
            $same_site = !empty($entry['same_site']);

            Won2_Logger::init()->log($type, $url, $host, $status, $reason, $source, $blocked, $same_site);
        }
    }
}
}