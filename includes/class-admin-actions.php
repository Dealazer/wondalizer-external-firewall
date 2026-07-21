<?php
/**
 * Wondalizer External Firewall — Admin Actions (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Admin_Actions')) {
class Won2_Admin_Actions {
    private static $instance = null;

    public static function init() {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        add_action('admin_init', [$this, 'handle_forms']);
    }

    public static function is_protected_folder($folder) {
        $folder = strtolower($folder);
        return (strpos($folder, 'wondalizer-external-firewall') !== false || strpos($folder, 'wondalizer-fw') !== false);
    }

    public static function update_option_fresh($option, $value, $autoload = 'yes') {
        global $wpdb;
        if (!isset($wpdb) || !($wpdb instanceof wpdb)) {
            wp_cache_delete($option, 'options');
            wp_cache_delete('alloptions', 'options');
            $result = update_option($option, $value, $autoload);
            wp_cache_delete($option, 'options');
            wp_cache_delete('alloptions', 'options');
            return $result;
        }

        $serialized = maybe_serialize($value);
        $autoload_val = ($autoload === 'yes' || $autoload === true) ? 'yes' : 'no';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- intentional direct DB for cache bypass
        $exists = $wpdb->get_var($wpdb->prepare("SELECT option_id FROM $wpdb->options WHERE option_name = %s LIMIT 1", $option));
        if ($exists) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- intentional direct DB for cache bypass
            $wpdb->update($wpdb->options, ['option_value' => $serialized, 'autoload' => $autoload_val], ['option_name' => $option]);
        } else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- intentional direct DB for cache bypass
            $wpdb->insert($wpdb->options, ['option_name' => $option, 'option_value' => $serialized, 'autoload' => $autoload_val]);
        }

        wp_cache_delete($option, 'options');
        wp_cache_delete('alloptions', 'options');
        wp_cache_delete('notoptions', 'options');
        wp_cache_delete($option, 'won2_mu_options');
        if (function_exists('wp_cache_flush')) {
            wp_cache_flush();
        }

        return true;
    }

    public static function get_option_direct($option, $default = []) {
        global $wpdb;
        if (isset($wpdb) && $wpdb instanceof wpdb) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- intentional direct DB for cache bypass
            $row = $wpdb->get_row($wpdb->prepare("SELECT option_value FROM $wpdb->options WHERE option_name = %s", $option));
            if ($row) {
                $val = maybe_unserialize($row->option_value);
                if (is_array($default) && !is_array($val)) {
                    $val = array();
                }
                return $val;
            }
        }
        $val = get_option($option, $default);
        if (is_array($default) && !is_array($val)) {
            $val = array();
        }
        return $val;
    }

    public static function normalize_array($arr) {
        return array_values(array_unique(array_filter(array_map(function($v) {
            return strtolower(trim((string)$v));
        }, (array)$arr))));
    }

    public static function remove_from_array($arr, $value) {
        $target = strtolower(trim((string)$value));
        return array_values(array_filter((array)$arr, function($item) use ($target) {
            return strtolower(trim((string)$item)) !== $target;
        }));
    }

    // phpcs:disable WordPress.Security.NonceVerification.Missing -- called from handle_forms() after nonce verification
    private function get_selected_folders($data = null) {
        if ($data === null) $data = $_POST;
        $folders = [];
        foreach (['selected_plugins', 'bulk_selected', 'single_folder'] as $key) {
            if (isset($data[$key])) {
                $val = wp_unslash($data[$key]);
                if (is_array($val)) {
                    $folders = array_merge($folders, $val);
                } elseif (is_string($val) && $val !== '') {
                    $exploded = explode(',', $val);
                    $folders = array_merge($folders, $exploded);
                }
            }
        }
        return array_values(array_unique(array_filter(array_map(function($f) {
            return sanitize_text_field(trim($f));
        }, $folders))));
    }
    // phpcs:enable WordPress.Security.NonceVerification.Missing

    // phpcs:disable WordPress.Security.NonceVerification.Missing -- nonce verified by check_admin_referer() below
    public function handle_forms() {
    // phpcs:enable WordPress.Security.NonceVerification.Missing
        if (!current_user_can('manage_options')) return;
        if (empty($_POST) || !isset($_POST['won2_action'])) return;

        $action = sanitize_key($_POST['won2_action']);
        check_admin_referer('won2_action', 'won2_nonce');

        switch ($action) {
            case 'save_settings':
                $this->save_settings();
                break;
            case 'bulk_block':
            case 'block':
            case 'bulk_allow':
            case 'unblock':
            case 'bulk_block_email':
            case 'block_email':
            case 'bulk_unblock_email':
            case 'unblock_email':
            case 'bulk_rewrite':
            case 'rewrite':
            case 'bulk_restore':
            case 'restore':
                $this->handle_bulk($action, $_POST);
                break;
            case 'save_domains':
                $this->save_domains();
                break;
            case 'bulk_cron_allow':
            case 'bulk_cron_block':
            case 'block_cron_hook':
            case 'unblock_cron_hook':
            case 'allow_cron_hook':
            case 'disallow_cron_hook':
            case 'block_all_cron':
            case 'unblock_all_cron':
            case 'allow_all_cron':
            case 'disallow_all_cron':
                $this->handle_cron_bulk($action, $_POST);
                break;
            case 'clear_logs':
                $this->clear_logs();
                break;
            case 'block_obs':
            case 'unblock_obs':
                $this->handle_obfuscation($action, $_POST);
                break;
            case 'rescan':
                if (class_exists('Won2_Scan') && method_exists('Won2_Scan', 'clear_scan_cache')) {
                    Won2_Scan::clear_scan_cache();
                }
                set_transient('won1_force_rescan_v3', true, 300);
                break;
            case 'block_all':
            case 'unblock_all':
            case 'block_core_http':
            case 'unblock_core_http':
            case 'block_themes_http':
            case 'unblock_themes_http':
                $this->handle_http_bulk_toggles($action, $_POST);
                break;
            case 'block_all_emails':
            case 'unblock_all_emails':
                $this->handle_email_bulk_toggles($action, $_POST);
                break;
            case 'block_all_obs':
            case 'unblock_all_obs':
                $this->handle_obs_bulk_toggles($action, $_POST);
                break;
        }

        // Single centralized cache clear at the end
        Won2_Firewall::clear_block_caches();
        if (function_exists('wp_cache_flush')) wp_cache_flush();
        delete_transient('won1_roster_v3');
        delete_transient('won1_roster_v3_partial');
        delete_transient('won1_roster_incomplete');
        wp_cache_delete('won1_roster_v3', 'transient');
        wp_cache_delete('won1_roster_v3_partial', 'transient');
        wp_cache_delete('won1_roster_incomplete', 'transient');

        if (!wp_doing_ajax()) {
            $tab = isset($_POST['won1_tab']) ? sanitize_key($_POST['won1_tab']) : 'settings';
            $roster_actions = ['block','unblock','bulk_block','bulk_allow','block_all','unblock_all','block_core_http','unblock_core_http','block_themes_http','unblock_themes_http','bulk_rewrite','rewrite','bulk_restore','restore','block_obs','unblock_obs','block_all_obs','unblock_all_obs', 'rescan'];
            $email_actions = ['block_email','unblock_email','bulk_block_email','bulk_unblock_email','block_all_emails','unblock_all_emails','block_core_emails','unblock_core_emails','block_themes_emails','unblock_themes_emails'];
            $cron_actions = ['block_cron_hook','unblock_cron_hook','allow_cron_hook','disallow_cron_hook','bulk_cron_block','bulk_cron_allow','block_all_cron','unblock_all_cron','allow_all_cron','disallow_all_cron'];

            if (in_array($action, $roster_actions, true)) {
                $tab = 'roster';
            } elseif (in_array($action, $email_actions, true)) {
                $tab = 'emails';
            } elseif (in_array($action, $cron_actions, true)) {
                $tab = 'cron';
            }
            wp_safe_redirect(admin_url('admin.php?page=' . WON2_SLUG . '&msg=updated&won1_msg_nonce=' . wp_create_nonce('won1_msg_action') . '#' . $tab));
            exit;
        }
    }

    // phpcs:disable WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- called from handle_forms() after nonce verification; settings array sanitized below
    private function save_settings() {
        $settings = self::get_option_direct('won2_firewall_settings', []);
        if (!is_array($settings)) $settings = [];
        $post_settings = isset($_POST['settings']) && is_array($_POST['settings']) ? wp_unslash($_POST['settings']) : [];
        $is_full_form = !empty($_POST['won1_full_settings_form']);

        if ($is_full_form) {
            $bool_fields = [
                'http_firewall_enabled', 'cron_firewall_enabled', 'logging_enabled',
                'log_http_blocked', 'log_http_allowed', 'log_email_blocked',
                'log_email_allowed', 'log_internal_http', 'curl_cache_enabled',
                'block_recaptcha', 'cron_block_by_default', 'curl_cache_understood',
                'rw_curl', 'rw_sock', 'rw_mail', 'auto_rewrite_curl',
                'block_by_default', 'block_emails_by_default', 'block_themes_by_default', 'block_theme_emails_by_default',
                'whitelist_woocommerce', 'whitelist_edd', 'whitelist_paypal',
                'allow_same_site_for_blocked', 'hard_block_mode',
            ];
            foreach ($bool_fields as $f) {
                $settings[$f] = false;
            }
        }

        foreach ($post_settings as $key => $value) {
            $key = sanitize_key($key);
            if (is_array($value)) {
                $settings[$key] = array_map('sanitize_text_field', wp_unslash($value));
            } elseif (is_string($value) || is_numeric($value) || is_bool($value)) {
                $sanitized = sanitize_text_field(wp_unslash($value));
                if ($sanitized === '1' || $sanitized === 'true' || $sanitized === 'on') {
                    $settings[$key] = true;
                } elseif ($sanitized === '0' || $sanitized === 'false' || $sanitized === 'off') {
                    $settings[$key] = false;
                } else {
                    $settings[$key] = $sanitized;
                }
            }
        }

        if ($is_full_form) {
            if (isset($post_settings['whitelist'])) {
                $wl = array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', sanitize_textarea_field(wp_unslash($post_settings['whitelist'])))));
                $settings['whitelist'] = $wl;
                $this->update_option_fresh('won1_whitelist_domains', $wl, 'yes');
            } else {
                $settings['whitelist'] = [];
                $this->update_option_fresh('won1_whitelist_domains', [], 'yes');
            }

            if (isset($post_settings['blocked_domains'])) {
                $bl = array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', sanitize_textarea_field(wp_unslash($post_settings['blocked_domains'])))));
                $settings['blocked_domains'] = $bl;
                $this->update_option_fresh('won1_blacklist_domains', $bl, 'yes');
            } else {
                $settings['blocked_domains'] = [];
                $this->update_option_fresh('won1_blacklist_domains', [], 'yes');
            }

            if (isset($post_settings['allowed_domains'])) {
                $ad = array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', sanitize_textarea_field(wp_unslash($post_settings['allowed_domains'])))));
                $settings['allowed_domains'] = $ad;
            } else {
                $settings['allowed_domains'] = [];
            }

            if (isset($post_settings['retention_days'])) {
                $settings['retention_days'] = max(1, min(90, (int)$post_settings['retention_days']));
            }
        }

        if (!empty($_POST['whitelist_wp_core'])) {
            $wl = self::get_option_direct('won1_whitelist_domains', []);
            if (!is_array($wl)) $wl = [];
            $core_domains = [
                'wordpress.org', 'api.wordpress.org', 'downloads.wordpress.org',
                'planet.wordpress.org', 'core.trac.wordpress.org', 'meta.trac.wordpress.org',
                'ps.w.org', 's.w.org', 'wordpress.com', 'jetpack.wordpress.com',
                'public-api.wordpress.com', 'stats.wordpress.com'
            ];
            $wl = array_unique(array_merge($wl, $core_domains));
            $this->update_option_fresh('won1_whitelist_domains', $wl, 'yes');
            $settings['whitelist'] = $wl;
        }

        if (!empty($_POST['whitelist_recaptcha'])) {
            $wl = self::get_option_direct('won1_whitelist_domains', []);
            if (!is_array($wl)) $wl = [];
            $recaptcha_domains = ['google.com', 'gstatic.com', 'recaptcha.net'];
            $wl = array_unique(array_merge($wl, $recaptcha_domains));
            $this->update_option_fresh('won1_whitelist_domains', $wl, 'yes');
            $settings['whitelist'] = $wl;
        }

        $this->update_option_fresh('won2_firewall_settings', $settings, 'yes');
        Won2_Firewall::refresh_settings();
        if (function_exists('wp_cache_flush')) wp_cache_flush();
        Won2_Logger::refresh_settings();

        delete_transient('won1_roster_v3');
        delete_transient('won1_roster_v3_partial');
    }
    // phpcs:enable WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

    private function handle_bulk($action, $data = null) {
        $folders = $this->get_selected_folders($data);
        if (empty($folders)) return;

        $scan = null;
        if (in_array($action, ['bulk_rewrite', 'rewrite', 'bulk_restore', 'restore'], true)) {
            if (!class_exists('Won2_Scan')) {
                $scan_file = WON2_DIR . 'includes/class-scan.php';
                if (file_exists($scan_file)) {
                    require_once $scan_file;
                }
            }
            if (class_exists('Won2_Scan')) {
                $scan = new Won2_Scan();
            }
        }

        foreach ($folders as $folder) {
            if (Won2_Scan::is_protected_folder($folder)) continue;
            $folder_lc = strtolower(trim($folder));

            switch ($action) {
                case 'bulk_block':
                case 'block':
                    $blocked = (array) self::get_option_direct('won2_blocked_plugins', []);
                    if (!in_array($folder_lc, $blocked, true)) {
                        $blocked[] = $folder_lc;
                    }
                    $this->update_option_fresh('won2_blocked_plugins', $this->normalize_array($blocked), 'yes');

                    $allowed = (array) self::get_option_direct('won2_allowed_plugins', []);
                    $allowed = $this->remove_from_array($allowed, $folder);
                    $this->update_option_fresh('won2_allowed_plugins', $allowed, 'yes');
                    break;

                case 'bulk_allow':
                case 'unblock':
                    // Remove every core alias as well: older versions listed
                    // core as 'core' or 'wp-core' and those entries block too.
                    $core_aliases = ['wordpress-core', 'wp-core', 'core', 'wp-admin', 'wp-includes'];
                    $targets = in_array($folder_lc, $core_aliases, true) ? $core_aliases : [$folder];

                    $blocked = (array) self::get_option_direct('won2_blocked_plugins', []);
                    foreach ($targets as $t) {
                        $blocked = $this->remove_from_array($blocked, $t);
                    }
                    $this->update_option_fresh('won2_blocked_plugins', $blocked, 'yes');

                    $allowed = (array) self::get_option_direct('won2_allowed_plugins', []);
                    if (!in_array($folder_lc, $allowed, true)) {
                        $allowed[] = $folder_lc;
                    }
                    $this->update_option_fresh('won2_allowed_plugins', $this->normalize_array($allowed), 'yes');

                    $blocked_obs = (array) self::get_option_direct('won2_blocked_obfuscation', []);
                    foreach ($targets as $t) {
                        $blocked_obs = $this->remove_from_array($blocked_obs, $t);
                    }
                    $this->update_option_fresh('won2_blocked_obfuscation', $blocked_obs, 'yes');
                    break;

                case 'bulk_block_email':
                case 'block_email':
                    $blocked = (array) self::get_option_direct('won2_blocked_emails', []);
                    if (!in_array($folder_lc, $blocked, true)) {
                        $blocked[] = $folder_lc;
                    }
                    $this->update_option_fresh('won2_blocked_emails', $this->normalize_array($blocked), 'yes');

                    $allowed = (array) self::get_option_direct('won2_allowed_emails', []);
                    $allowed = $this->remove_from_array($allowed, $folder);
                    $this->update_option_fresh('won2_allowed_emails', $allowed, 'yes');
                    break;

                case 'bulk_unblock_email':
                case 'unblock_email':
                    $blocked = (array) self::get_option_direct('won2_blocked_emails', []);
                    $blocked = $this->remove_from_array($blocked, $folder);
                    $this->update_option_fresh('won2_blocked_emails', $blocked, 'yes');

                    $allowed = (array) self::get_option_direct('won2_allowed_emails', []);
                    if (!in_array($folder_lc, $allowed, true)) {
                        $allowed[] = $folder_lc;
                    }
                    $this->update_option_fresh('won2_allowed_emails', $this->normalize_array($allowed), 'yes');
                    break;

                case 'bulk_rewrite':
                case 'rewrite':
                    if ($scan !== null) {
                        $res = $scan->rewrite_extension($folder);
                        if ($res['success']) {
                            $rewritten = (array) self::get_option_direct('won2_rewritten_plugins', []);
                            $rewritten[$folder] = ['curl'=>true,'sock'=>true,'mail'=>true];
                            $this->update_option_fresh('won2_rewritten_plugins', $rewritten, 'yes');
                        }
                    }
                    break;

                case 'bulk_restore':
                case 'restore':
                    if ($scan !== null) {
                        $res = $scan->restore_extension($folder);
                        if ($res['success']) {
                            $rewritten = (array) self::get_option_direct('won2_rewritten_plugins', []);
                            unset($rewritten[$folder]);
                            $this->update_option_fresh('won2_rewritten_plugins', $rewritten, 'yes');
                        }
                    }
                    break;
            }
        }
        if ($scan !== null) {
            $scan->save_cache();
        }
    }

    // phpcs:disable WordPress.Security.NonceVerification.Missing -- called from handle_forms() after nonce verification
    private function save_domains() {
        $whitelist = isset($_POST['whitelist_domains']) ? sanitize_textarea_field(wp_unslash($_POST['whitelist_domains'])) : '';
        $blacklist = isset($_POST['blacklist_domains']) ? sanitize_textarea_field(wp_unslash($_POST['blacklist_domains'])) : '';
        $wl = array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', $whitelist)));
        $bl = array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', $blacklist)));
        $this->update_option_fresh('won1_whitelist_domains', $wl, 'yes');
        $this->update_option_fresh('won1_blacklist_domains', $bl, 'yes');
        if (function_exists('wp_cache_flush')) wp_cache_flush();

        $settings = self::get_option_direct('won2_firewall_settings', []);
        if (is_array($settings)) {
            $settings['whitelist'] = $wl;
            $settings['blocked_domains'] = $bl;
            $this->update_option_fresh('won2_firewall_settings', $settings, 'yes');
        }

        Won2_Firewall::refresh_settings();

        delete_transient('won1_roster_v3');
        delete_transient('won1_roster_v3_partial');
    }
    // phpcs:enable WordPress.Security.NonceVerification.Missing

    // phpcs:disable WordPress.Security.NonceVerification.Missing -- called from handle_forms() after nonce verification
    private function handle_cron_bulk($action, $data = null) {
        $selected = isset($_POST['selected_hooks']) ? sanitize_text_field(wp_unslash($_POST['selected_hooks'])) : '';
        if (empty($selected)) {
            $selected = isset($_POST['bulk_selected_cron']) ? sanitize_text_field(wp_unslash($_POST['bulk_selected_cron'])) : '';
        }
        if (empty($selected)) {
            $selected = isset($_POST['cron_hook']) ? sanitize_text_field(wp_unslash($_POST['cron_hook'])) : '';
        }

        $hooks = array_filter(array_map('sanitize_text_field', explode(',', $selected)));
        if (empty($hooks) && !in_array($action, ['block_all_cron', 'unblock_all_cron', 'allow_all_cron', 'disallow_all_cron'], true)) {
            return;
        }

        $blocked = (array) self::get_option_direct('won2_blocked_cron_hooks', []);
        $allowed = (array) self::get_option_direct('won2_allowed_cron_hooks', []);

        if ($action === 'bulk_cron_block' || $action === 'block_cron_hook') {
            foreach ($hooks as $h) {
                if (!in_array($h, $blocked, true)) $blocked[] = $h;
            }
            $blocked = array_values(array_unique($blocked));
        } elseif ($action === 'bulk_cron_allow' || $action === 'allow_cron_hook') {
            foreach ($hooks as $h) {
                if (!in_array($h, $allowed, true)) $allowed[] = $h;
            }
            $allowed = array_values(array_unique($allowed));
        } elseif ($action === 'unblock_cron_hook') {
            $blocked = array_diff($blocked, $hooks);
        } elseif ($action === 'disallow_cron_hook') {
            $allowed = array_diff($allowed, $hooks);
        } elseif (in_array($action, ['block_all_cron', 'unblock_all_cron', 'allow_all_cron', 'disallow_all_cron'], true)) {
            $crons = get_option('cron', []);
            $all_hooks = [];
            if (is_array($crons)) {
                foreach ($crons as $timestamp => $cronhooks) {
                    foreach ((array)$cronhooks as $hook => $args) {
                        $all_hooks[] = $hook;
                    }
                }
            }
            $all_hooks = array_unique($all_hooks);
            foreach ($all_hooks as $hook) {
                if ($action === 'block_all_cron') {
                    if (!in_array($hook, $blocked, true)) $blocked[] = $hook;
                } elseif ($action === 'unblock_all_cron') {
                    $blocked = array_diff($blocked, [$hook]);
                } elseif ($action === 'allow_all_cron') {
                    if (!in_array($hook, $allowed, true)) $allowed[] = $hook;
                } elseif ($action === 'disallow_all_cron') {
                    $allowed = array_diff($allowed, [$hook]);
                }
            }
            $blocked = array_values(array_unique($blocked));
            $allowed = array_values(array_unique($allowed));
        }

        $this->update_option_fresh('won2_blocked_cron_hooks', array_values($blocked), 'yes');
        $this->update_option_fresh('won2_allowed_cron_hooks', array_values($allowed), 'yes');

        Won2_Firewall::clear_block_caches();
        if (function_exists('wp_cache_flush')) wp_cache_flush();
    }

    // phpcs:enable WordPress.Security.NonceVerification.Missing
    private function handle_obfuscation($action, $data = null) {
        $folders = $this->get_selected_folders($data);
        if (empty($folders)) return;

        $blocked = (array) self::get_option_direct('won2_blocked_obfuscation', []);
        foreach ($folders as $folder) {
            if (Won2_Scan::is_protected_folder($folder)) continue;
            if ($action === 'block_obs') {
                $blocked[] = strtolower(trim($folder));
            } else {
                $blocked = $this->remove_from_array($blocked, $folder);
            }
        }
        $this->update_option_fresh('won2_blocked_obfuscation', $this->normalize_array($blocked), 'yes');
    }

    private function handle_http_bulk_toggles($action, $data = null) {
        $roster = Won2_Admin_Roster::get_plugin_roster();
        $blocked = (array) self::get_option_direct('won2_blocked_plugins', []);
        $allowed = (array) self::get_option_direct('won2_allowed_plugins', []);
        foreach ($roster as $p) {
            if (Won2_Scan::is_protected_folder($p['folder'])) continue;
            $folder = strtolower(trim($p['folder']));
            if ($action === 'block_all') {
                if (!in_array($folder, $blocked, true)) $blocked[] = $folder;
                $allowed = $this->remove_from_array($allowed, $folder);
            } elseif ($action === 'unblock_all') {
                $blocked = $this->remove_from_array($blocked, $folder);
                if (!in_array($folder, $allowed, true)) $allowed[] = $folder;
            } elseif ($action === 'block_core_http' && $p['is_core']) {
                if (!in_array($folder, $blocked, true)) $blocked[] = $folder;
                $allowed = $this->remove_from_array($allowed, $folder);
            } elseif ($action === 'unblock_core_http' && $p['is_core']) {
                $blocked = $this->remove_from_array($blocked, $folder);
                if (!in_array($folder, $allowed, true)) $allowed[] = $folder;
            } elseif ($action === 'block_themes_http' && $p['type'] === 'theme') {
                if (!in_array($folder, $blocked, true)) $blocked[] = $folder;
                $allowed = $this->remove_from_array($allowed, $folder);
            } elseif ($action === 'unblock_themes_http' && $p['type'] === 'theme') {
                $blocked = $this->remove_from_array($blocked, $folder);
                if (!in_array($folder, $allowed, true)) $allowed[] = $folder;
            }
        }
        $this->update_option_fresh('won2_blocked_plugins', $this->normalize_array($blocked), 'yes');
        $this->update_option_fresh('won2_allowed_plugins', $this->normalize_array($allowed), 'yes');

        if (in_array($action, ['unblock_all', 'unblock_core_http', 'unblock_themes_http'], true)) {
            $blocked_obs = (array) self::get_option_direct('won2_blocked_obfuscation', []);
            foreach ($roster as $p) {
                if (Won2_Scan::is_protected_folder($p['folder'])) continue;
                $folder = strtolower(trim($p['folder']));
                if ($action === 'unblock_all') {
                    $blocked_obs = $this->remove_from_array($blocked_obs, $folder);
                } elseif ($action === 'unblock_core_http' && $p['is_core']) {
                    $blocked_obs = $this->remove_from_array($blocked_obs, $folder);
                } elseif ($action === 'unblock_themes_http' && $p['type'] === 'theme') {
                    $blocked_obs = $this->remove_from_array($blocked_obs, $folder);
                }
            }
            $this->update_option_fresh('won2_blocked_obfuscation', $this->normalize_array($blocked_obs), 'yes');
        }
    }

    private function handle_email_bulk_toggles($action, $data = null) {
        $roster = Won2_Admin_Roster::get_plugin_roster();
        $blocked = (array) self::get_option_direct('won2_blocked_emails', []);
        $allowed = (array) self::get_option_direct('won2_allowed_emails', []);
        foreach ($roster as $p) {
            if (Won2_Scan::is_protected_folder($p['folder'])) continue;
            $folder = strtolower(trim($p['folder']));
            if ($action === 'block_all_emails') {
                if (!in_array($folder, $blocked, true)) $blocked[] = $folder;
                $allowed = $this->remove_from_array($allowed, $folder);
            } elseif ($action === 'unblock_all_emails') {
                $blocked = $this->remove_from_array($blocked, $folder);
                if (!in_array($folder, $allowed, true)) $allowed[] = $folder;
            } elseif ($action === 'block_core_emails' && $p['is_core']) {
                if (!in_array($folder, $blocked, true)) $blocked[] = $folder;
                $allowed = $this->remove_from_array($allowed, $folder);
            } elseif ($action === 'unblock_core_emails' && $p['is_core']) {
                $blocked = $this->remove_from_array($blocked, $folder);
                if (!in_array($folder, $allowed, true)) $allowed[] = $folder;
            } elseif ($action === 'block_themes_emails' && $p['type'] === 'theme') {
                if (!in_array($folder, $blocked, true)) $blocked[] = $folder;
                $allowed = $this->remove_from_array($allowed, $folder);
            } elseif ($action === 'unblock_themes_emails' && $p['type'] === 'theme') {
                $blocked = $this->remove_from_array($blocked, $folder);
                if (!in_array($folder, $allowed, true)) $allowed[] = $folder;
            }
        }
        $this->update_option_fresh('won2_blocked_emails', $this->normalize_array($blocked), 'yes');
        $this->update_option_fresh('won2_allowed_emails', $this->normalize_array($allowed), 'yes');
    }

    private function handle_obs_bulk_toggles($action, $data = null) {
        $roster = Won2_Admin_Roster::get_plugin_roster();
        $blocked = (array) self::get_option_direct('won2_blocked_obfuscation', []);
        foreach ($roster as $p) {
            if (Won2_Scan::is_protected_folder($p['folder'])) continue;
            if (!empty($p['has_obfuscated'])) {
                $folder = strtolower(trim($p['folder']));
                if ($action === 'block_all_obs') {
                    if (!in_array($folder, $blocked, true)) $blocked[] = $folder;
                } else {
                    $blocked = $this->remove_from_array($blocked, $folder);
                }
            }
        }
        $this->update_option_fresh('won2_blocked_obfuscation', $this->normalize_array($blocked), 'yes');
    }

    private function clear_logs() {
        if (class_exists('Won2_Logger')) {
            Won2_Logger::init()->cleanup(0);
        }
        $this->update_option_fresh('won1_intercept_buffer', [], false);
        $this->update_option_fresh('won1_live_captures', [], false);
        if (function_exists('wp_cache_flush')) wp_cache_flush();
    }
}
}