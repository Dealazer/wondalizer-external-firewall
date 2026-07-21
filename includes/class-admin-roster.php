<?php
/**
 * Wondalizer External Firewall — Admin Roster (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Admin_Roster')) {
class Won2_Admin_Roster {
    const ROSTER_VERSION = '8.1.8';

    private static function is_protected_folder($folder) {
        if (class_exists('Won2_Admin_Actions') && method_exists('Won2_Admin_Actions', 'is_protected_folder')) {
            return Won2_Admin_Actions::is_protected_folder($folder);
        }
        $folder = strtolower($folder);
        return (strpos($folder, 'wondalizer-external-firewall') !== false || strpos($folder, 'wondalizer-fw') !== false);
    }

    private static function get_option_direct($option, $default = []) {
        if (class_exists('Won2_Admin_Actions') && method_exists('Won2_Admin_Actions', 'get_option_direct')) {
            return Won2_Admin_Actions::get_option_direct($option, $default);
        }
        $val = get_option($option, $default);
        if (is_array($default) && !is_array($val)) $val = [];
        return $val;
    }

    public static function get_plugin_roster() {
        $cached = get_transient('won1_roster_v3');
        $force_rescan = get_transient('won1_force_rescan_v3');

        $has_non_core = false;
        if (is_array($cached)) {
            foreach ($cached as $item) {
                if (is_array($item) && isset($item['folder']) && $item['folder'] !== 'wordpress-core') {
                    $has_non_core = true;
                    break;
                }
            }
        }

        if (!$force_rescan && $has_non_core && is_array($cached) && isset($cached['_scan_version']) && $cached['_scan_version'] === self::ROSTER_VERSION) {
            unset($cached['_scan_version']);
            return self::apply_dynamic_statuses($cached);
        }

        if ($force_rescan) {
            delete_transient('won1_force_rescan_v3');
            delete_transient('won1_roster_v3');
            delete_transient('won1_roster_v3_partial');
            delete_transient('won1_roster_incomplete');
        }

        $partial = get_transient('won1_roster_v3_partial');
        if (!$force_rescan && is_array($partial) && isset($partial['_scan_version']) && $partial['_scan_version'] === self::ROSTER_VERSION) {
            unset($partial['_scan_version']);
            $roster = $partial;
        } else {
            $roster = [];

            if (!function_exists('get_plugins')) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }

            if (function_exists('get_plugins')) {
                $plugins = get_plugins();
                foreach ($plugins as $file => $data) {
                    $folder = dirname($file);
                    if ($folder === '.' || $folder === '') $folder = $file;
                    $folder_parts = explode('/', $folder);
                    $folder = $folder_parts[0];
                    $roster[] = self::build_roster_item($data['Name'], $folder, 'plugin');
                }
            }

            if (function_exists('get_mu_plugins')) {
                $mu_plugins = get_mu_plugins();
                foreach ($mu_plugins as $file => $data) {
                    $folder = 'mu-' . sanitize_file_name(basename($file, '.php'));
                    $roster[] = self::build_roster_item($data['Name'], $folder, 'mu-plugin');
                }
            }

            if (function_exists('wp_get_themes')) {
                $themes = wp_get_themes();
                foreach ($themes as $slug => $theme) {
                    $roster[] = self::build_roster_item($theme->get('Name'), $slug, 'theme');
                }
            }

            $core_domains = class_exists('Won2_Scan') ? Won2_Scan::CORE_DOMAINS : [];
            $roster[] = [
                'name' => __('WordPress Core', 'wondalizer-external-firewall'),
                'folder' => 'wordpress-core',
                'type' => 'core',
                'is_core' => true,
                'scanned' => true,
                'has_curl' => false, 'has_curl_multi' => false, 'has_curl_share' => false,
                'has_curl_indirect' => false, 'has_curl_class' => false, 'has_curl_namespace' => false,
                'has_curl_file' => false, 'has_curl_easy' => false, 'has_curl_mime' => false,
                'has_curl_form' => false, 'has_curl_any' => false, 'has_curlopt' => false,
                'has_fsockopen' => false, 'has_socket_raw' => false, 'has_stream_socket' => false,
                'has_socket_extended' => false, 'has_stream_extended' => false, 'has_dns_lookup' => false,
                'has_socket_any' => false, 'has_stream_any' => false,
                'has_php_mail' => false, 'has_wp_mail' => false, 'has_phpmailer' => false,
                'has_smtp_class' => false, 'has_swiftmailer' => false,
                'has_mail_extended' => false, 'has_mail_any' => false, 'has_sendmail' => false,
                'has_wp_http' => true, 'has_wp_http_api' => false,
                'has_guzzle' => false, 'has_requests_lib' => false, 'has_http_client' => false,
                'has_rest_api' => false, 'has_xmlrpc' => false, 'has_soap' => false, 'has_ftp' => false,
                'has_wp_http_any' => false, 'has_file_get_contents' => false, 'has_fopen_any' => false,
                'has_copy_any' => false, 'has_readfile_any' => false, 'has_file_any' => false,
                'has_wp_http_obj' => false, 'has_requests_obj' => false,
                'has_symfony_http' => false, 'has_laravel_http' => false, 'has_react_http' => false, 'has_amp_http' => false,
                'scanned_domains' => $core_domains,
                'blocked_http' => false, 'blocked_email' => false, 'blocked_obs' => false,
                'has_obfuscated' => false, 'obs_score' => 0, 'obs_patterns' => [],
                'rewritten' => false, 'is_protected' => false, 'scan_version' => self::ROSTER_VERSION,
            ];
        }

        $incomplete = false;
        if (class_exists('Won2_Scan')) {
            $scan = new Won2_Scan();
            $start_time = microtime(true);
            $max_time = 12; // Safety execution window limit
            foreach ($roster as $key => $item) {
                if ($item['is_core'] || $item['is_protected']) continue;
                if (!empty($item['scanned'])) continue;

                if (microtime(true) - $start_time > $max_time) {
                    $incomplete = true;
                    break;
                }
                try {
                    $scan_res = $scan->scan_plugin($item['folder']);
                    if (is_array($scan_res)) {
                        foreach ($scan_res as $field => $val) {
                            if (array_key_exists($field, $roster[$key])) {
                                $roster[$key][$field] = $val;
                            }
                        }
                        if (isset($scan_res["domains"]) && is_array($scan_res["domains"])) {
                            $roster[$key]["scanned_domains"] = $scan_res["domains"];
                        }
                        $roster[$key]['scanned'] = true;
                    }
                } catch (\Throwable $e) {
                    $roster[$key]['scanned'] = true;
                }
            }
            $scan->save_cache();
        }

        if ($incomplete) {
            set_transient('won1_roster_v3_partial', array_merge($roster, ['_scan_version' => self::ROSTER_VERSION]), HOUR_IN_SECONDS);
            set_transient('won1_roster_incomplete', true, HOUR_IN_SECONDS);
        } else {
            delete_transient('won1_roster_v3_partial');
            delete_transient('won1_roster_incomplete');
            set_transient('won1_roster_v3', array_merge($roster, ['_scan_version' => self::ROSTER_VERSION]), HOUR_IN_SECONDS * 6);
        }

        return self::apply_dynamic_statuses($roster);
    }

    private static function build_roster_item($name, $folder, $type) {
        $is_protected = self::is_protected_folder($folder);
        return [
            'name' => $name,
            'folder' => $folder,
            'type' => $type,
            'is_core' => false,
            'scanned' => $is_protected,
            'has_curl' => false,
            'has_curl_multi' => false,
            'has_curl_share' => false,
            'has_curl_indirect' => false,
            'has_curl_class' => false,
            'has_curl_namespace' => false,
            'has_curl_file' => false,
            'has_curl_easy' => false,
            'has_curl_mime' => false,
            'has_curl_form' => false,
            'has_curl_any' => false,
            'has_curlopt' => false,
            'has_fsockopen' => false,
            'has_socket_raw' => false,
            'has_stream_socket' => false,
            'has_socket_extended' => false,
            'has_stream_extended' => false,
            'has_dns_lookup' => false,
            'has_socket_any' => false,
            'has_stream_any' => false,
            'has_php_mail' => false,
            'has_wp_mail' => false,
            'has_phpmailer' => false,
            'has_smtp_class' => false,
            'has_swiftmailer' => false,
            'has_mail_extended' => false,
            'has_mail_any' => false,
            'has_sendmail' => false,
            'has_wp_http' => false,
            'has_wp_http_api' => false,
            'has_guzzle' => false,
            'has_requests_lib' => false,
            'has_http_client' => false,
            'has_rest_api' => false,
            'has_xmlrpc' => false,
            'has_soap' => false,
            'has_ftp' => false,
            'has_wp_http_any' => false,
            'has_file_get_contents' => false,
            'has_fopen_any' => false,
            'has_copy_any' => false,
            'has_readfile_any' => false,
            'has_file_any' => false,
            'has_wp_http_obj' => false,
            'has_requests_obj' => false,
            'has_symfony_http' => false,
            'has_laravel_http' => false,
            'has_react_http' => false,
            'has_amp_http' => false,
            'scanned_domains' => [],
            'blocked_http' => false,
            'blocked_email' => false,
            'blocked_obs' => false,
            'has_obfuscated' => false,
            'obs_score' => 0,
            'obs_patterns' => [],
            'rewritten' => false,
            'is_protected' => $is_protected,
            'scan_version' => self::ROSTER_VERSION,
        ];
    }

    private static function apply_dynamic_statuses($roster) {
        if (!is_array($roster)) return [];

        $blocked_plugins = (array) self::get_option_direct('won2_blocked_plugins', []);
        $allowed_plugins = (array) self::get_option_direct('won2_allowed_plugins', []);
        $blocked_emails = (array) self::get_option_direct('won2_blocked_emails', []);
        $allowed_emails = (array) self::get_option_direct('won2_allowed_emails', []);
        $blocked_obs = (array) self::get_option_direct('won2_blocked_obfuscation', []);
        $rewritten_plugins = (array) self::get_option_direct('won2_rewritten_plugins', []);

        $settings = wp_parse_args(self::get_option_direct('won2_firewall_settings', []), [
            'block_by_default' => false,
            'block_emails_by_default' => false,
            'block_themes_by_default' => false,
            'block_theme_emails_by_default' => false,
        ]);

        $blocked_plugins_lower = array_map('strtolower', $blocked_plugins);
        $allowed_plugins_lower = array_map('strtolower', $allowed_plugins);
        $blocked_emails_lower = array_map('strtolower', $blocked_emails);
        $allowed_emails_lower = array_map('strtolower', $allowed_emails);
        $blocked_obs_lower = array_map('strtolower', $blocked_obs);

        foreach ($roster as &$item) {
            $folder_lower = strtolower($item['folder']);
            $is_plugin = ($item['type'] === 'plugin' || $item['type'] === 'mu-plugin');
            $is_theme = ($item['type'] === 'theme');

            // The firewall also enforces the obfuscation block list, and core
            // aliases from older versions ('core', 'wp-core') count as the same
            // entry as 'wordpress-core' — the badge must match the firewall.
            $core_aliases = ['wordpress-core', 'wp-core', 'core', 'wp-admin', 'wp-includes'];
            $lookup_names = in_array($folder_lower, $core_aliases, true) ? $core_aliases : [$folder_lower];
            if (array_intersect($lookup_names, $blocked_plugins_lower) || array_intersect($lookup_names, $blocked_obs_lower)) {
                $item['blocked_http'] = true;
            } elseif (array_intersect($lookup_names, $allowed_plugins_lower)) {
                $item['blocked_http'] = false;
            } else {
                if ($is_plugin && !empty($settings['block_by_default'])) {
                    $item['blocked_http'] = true;
                } elseif ($is_theme && !empty($settings['block_themes_by_default'])) {
                    $item['blocked_http'] = true;
                } else {
                    $item['blocked_http'] = false;
                }
            }

            if (in_array($folder_lower, $blocked_emails_lower, true)) {
                $item['blocked_email'] = true;
            } elseif (in_array($folder_lower, $allowed_emails_lower, true)) {
                $item['blocked_email'] = false;
            } else {
                if ($is_plugin && !empty($settings['block_emails_by_default'])) {
                    $item['blocked_email'] = true;
                } elseif ($is_theme && !empty($settings['block_theme_emails_by_default'])) {
                    $item['blocked_email'] = true;
                } else {
                    $item['blocked_email'] = false;
                }
            }

            $item['blocked_obs'] = in_array($folder_lower, $blocked_obs_lower, true);
            $item['rewritten'] = !empty($rewritten_plugins[$item['folder']]);

            if (!empty($item['is_protected'])) {
                $item['blocked_http'] = false;
                $item['blocked_email'] = false;
                $item['blocked_obs'] = false;
                $item['rewritten'] = false;
            }
        }
        return $roster;
    }

    public static function get_log_stats() {
        if (!class_exists('Won2_Logger')) {
            return ['http_logs' => 0, 'http_blocked' => 0, 'email_logs' => 0, 'email_blocked' => 0];
        }
        try {
            $logger = Won2_Logger::init();
            if (!method_exists($logger, 'get_stats')) {
                return ['http_logs' => 0, 'http_blocked' => 0, 'email_logs' => 0, 'email_blocked' => 0];
            }
            $stats = $logger->get_stats();
            if (!is_array($stats)) $stats = [];
            return [
                'http_logs' => isset($stats['http']) ? (int)$stats['http'] : 0,
                'http_blocked' => isset($stats['blocked']) ? (int)$stats['blocked'] : 0,
                'email_logs' => isset($stats['email']) ? (int)$stats['email'] : 0,
                'email_blocked' => isset($stats['blocked']) ? (int)$stats['blocked'] : 0,
            ];
        } catch (\Throwable $e) {
            return ['http_logs' => 0, 'http_blocked' => 0, 'email_logs' => 0, 'email_blocked' => 0];
        }
    }

    public static function get_log_counts_by_folder() {
        global $wpdb;
        $counts = ['http' => [], 'email' => []];

        if (!isset($wpdb) || !is_object($wpdb) || !method_exists($wpdb, 'get_var')) {
            return $counts;
        }

        $table = $wpdb->prefix . 'won2_logs';
        $cache_key = 'won2_roster_counts';
        $cached = wp_cache_get($cache_key, 'won2');
        if (is_array($cached)) {
            return $cached;
        }

        $wpdb->suppress_errors(true);
        try {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom table existence check required before aggregation query; wp_cache used for result caching.
            $exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
            if ($exists !== $table) {
                wp_cache_set($cache_key, $counts, 'won2', 30);
                return $counts;
            }

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Aggregating custom firewall log table; wp_cache used for result caching.
            $results = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT source_folder, type, status, COUNT(*) as cnt FROM %i WHERE source_folder != '' GROUP BY source_folder, type, status",
                    $table
                ),
                ARRAY_A
            );

            if (is_array($results)) {
                foreach ($results as $r) {
                    if (!is_array($r)) continue;
                    $folder = isset($r['source_folder']) ? $r['source_folder'] : '';
                    if (!$folder) continue;
                    $type = (isset($r['type']) && $r['type'] === 'email') ? 'email' : 'http';
                    if (!isset($counts[$type][$folder])) $counts[$type][$folder] = ['allowed' => 0, 'blocked' => 0];
                    $status = isset($r['status']) ? $r['status'] : '';
                    $cnt = isset($r['cnt']) ? (int)$r['cnt'] : 0;
                    if ($status === 'BLOCKED') $counts[$type][$folder]['blocked'] = $cnt;
                    else $counts[$type][$folder]['allowed'] = $cnt;
                }
            }
        } catch (\Throwable $e) {
            // Return empty counts on any DB error
        }
        $wpdb->suppress_errors(false);
        return $counts;
    }
}
}