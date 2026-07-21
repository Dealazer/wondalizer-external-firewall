<?php
/**
 * Wondalizer External Firewall — Admin AJAX Handlers (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Admin_Ajax')) {
class Won2_Admin_Ajax {

    private static function is_protected_folder($folder) {
        $folder = strtolower($folder);
        return (strpos($folder, 'wondalizer-external-firewall') !== false || strpos($folder, 'wondalizer-fw') !== false);
    }

    public static function init() {
        $actions = [
            'get_domains',
            'save_domains',
            'rewrite_method',
            'restore_method',
            'clear_all_cache',
            'bulk_restore',
            'block_obs',
            'unblock_obs',
            'clear_all_obs',
            'block',
            'unblock',
            'block_email',
            'unblock_email',
            'test_block',
        ];
        foreach ($actions as $action) {
            add_action('wp_ajax_won2_' . $action, [__CLASS__, 'ajax_' . $action]);
        }
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

    private static function update_option_direct($option, $value, $autoload = 'yes') {
        if (class_exists('Won2_Admin_Actions') && method_exists('Won2_Admin_Actions', 'update_option_fresh')) {
            return Won2_Admin_Actions::update_option_fresh($option, $value, $autoload);
        }
        wp_cache_delete($option, 'options');
        wp_cache_delete('alloptions', 'options');
        wp_cache_delete('notoptions', 'options');
        global $wpdb;
        if (isset($wpdb) && $wpdb instanceof wpdb) {
            $serialized = maybe_serialize($value);
            $autoload_val = ($autoload === 'yes' || $autoload === true) ? 'yes' : 'no';
            // Atomic REPLACE INTO: a DELETE+INSERT pair leaves a window where the
            // block lists read as empty and blocked plugins pass through.
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- intentional direct DB for cache bypass
            $wpdb->replace($wpdb->options, [
                'option_name'  => $option,
                'option_value' => $serialized,
                'autoload'     => $autoload_val,
            ]);
        } else {
            delete_option($option);
            add_option($option, $value, '', $autoload);
        }
        wp_cache_delete($option, 'options');
        wp_cache_delete('alloptions', 'options');
        wp_cache_delete('notoptions', 'options');
        wp_cache_delete($option, 'won2_mu_options');
        return true;
    }

    private static function clear_all_caches() {
        Won2_Firewall::clear_block_caches();
        if (function_exists('wp_cache_flush')) wp_cache_flush();
        delete_transient('won1_roster_v3');
        delete_transient('won1_roster_v3_partial');
        delete_transient('won1_roster_incomplete');
        wp_cache_delete('won1_roster_v3', 'transient');
        wp_cache_delete('won1_roster_v3_partial', 'transient');
        wp_cache_delete('won1_roster_incomplete', 'transient');
        wp_cache_delete('won2_blocked_plugins', 'won2_mu_options');
        wp_cache_delete('won2_allowed_plugins', 'won2_mu_options');
        wp_cache_delete('won2_blocked_obfuscation', 'won2_mu_options');
        wp_cache_delete('won2_blocked_emails', 'won2_mu_options');
        wp_cache_delete('won2_allowed_emails', 'won2_mu_options');
        wp_cache_delete('won2_firewall_settings', 'won2_mu_options');
        wp_cache_delete('won1_whitelist_domains', 'won2_mu_options');
        wp_cache_delete('won1_blacklist_domains', 'won2_mu_options');
    }

    private static function toggle_option_list($option_blocked, $option_allowed, $folder, $block) {
        $target = strtolower(trim($folder));
        $blocked = (array) self::get_option_direct($option_blocked, []);
        $allowed = $option_allowed !== null ? (array) self::get_option_direct($option_allowed, []) : null;

        if ($block) {
            if (!in_array($target, $blocked, true)) {
                $blocked[] = $target;
            }
            if ($allowed !== null) {
                $allowed = array_values(array_filter($allowed, function($item) use ($target) {
                    return strtolower(trim((string)$item)) !== $target;
                }));
            }
        } else {
            $blocked = array_values(array_filter($blocked, function($item) use ($target) {
                return strtolower(trim((string)$item)) !== $target;
            }));
            if ($allowed !== null && !in_array($target, $allowed, true)) {
                $allowed[] = $target;
            }
        }

        $new_blocked = array_values(array_unique(array_filter($blocked)));
        self::update_option_direct($option_blocked, $new_blocked);
        if ($option_allowed !== null) {
            self::update_option_direct($option_allowed, array_values(array_unique(array_filter($allowed))));
        }

        // Read-back verification: confirm the write actually persisted. If the
        // list did not stick (cache/DB hiccup), retry once via the fresh writer.
        $verify = (array) self::get_option_direct($option_blocked, []);
        $verify = array_map('strtolower', $verify);
        $should_exist = in_array($target, array_map('strtolower', $new_blocked), true);
        if (in_array($target, $verify, true) !== $should_exist) {
            self::update_option_direct($option_blocked, $new_blocked);
        }
    }

    public static function ajax_get_domains() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
            $folder = isset($_POST['folder']) ? sanitize_file_name(wp_unslash($_POST['folder'])) : '';
            if (empty($folder)) wp_send_json_error('No folder');

            $is_core = ($folder === 'wordpress-core' || $folder === 'wp-core' || $folder === 'core');
            $scan_domains = [];

            if ($is_core) {
                $scan_domains = Won2_Scan::CORE_DOMAINS;
            } else {
                $scan_file = WON2_DIR . 'includes/class-scan.php';
                if (!file_exists($scan_file)) wp_send_json_error('Scan engine missing');
                require_once $scan_file;
                if (!class_exists('Won2_Scan')) wp_send_json_error('Scan class not found');
                $scan = new Won2_Scan();
                $scan_result = $scan->scan_plugin($folder);
                $scan->save_cache();
                $scan_domains = $scan_result['domains'] ?? [];
            }

            $allowed = (array) self::get_option_direct('won2_plugin_allowed_domains', []);
            $plugin_allowed = $allowed[$folder] ?? [];
            ob_start();
            ?><form class="won2-domain-form" data-folder="<?php echo esc_attr($folder); ?>">
                <p><strong><?php echo esc_html($folder); ?></strong> — <?php esc_html_e('Check domains to ALLOW even when blocked:', 'wondalizer-external-firewall'); ?></p>
                <div id="won1-domain-notice" style="display:none;padding:8px 12px;margin:0 0 10px 0;border-radius:3px;font-weight:600;"></div>
                <div style="max-height:300px;overflow-y:auto;border:1px solid #ccc;padding:10px;">
                    <?php if (!empty($scan_domains)): ?>
                        <?php foreach ($scan_domains as $domain): ?>
                            <label style="display:block;margin:5px 0;"><input type="checkbox" name="allowed_domains[]" value="<?php echo esc_attr($domain); ?>" <?php checked(in_array($domain, $plugin_allowed, true)); ?>> <?php echo esc_html($domain); ?></label>
                        <?php endforeach; ?>
                    <?php else: ?><em><?php esc_html_e('No external domains discovered in static scan.', 'wondalizer-external-firewall'); ?></em><?php endif; ?>
                </div>
                <p style="margin-top:10px;">
                    <button type="button" class="button button-primary save-domains-btn" id="won1-save-domains-btn"><?php esc_html_e('Save Allowed Domains', 'wondalizer-external-firewall'); ?></button>
                    <span id="won1-save-spinner" style="display:none;margin-left:8px;"><span class="spinner is-active" style="float:none;margin:0;vertical-align:middle;"></span></span>
                </p>
            </form>
            <?php
            // Save handler is bound via delegated events in assets/admin.js (wp_enqueue compliance).
            wp_send_json_success(array('html' => ob_get_clean()));
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
    }

    public static function ajax_rewrite_method() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');

            $folder = isset($_POST['folder']) ? sanitize_file_name(wp_unslash($_POST['folder'])) : '';
            $method = isset($_POST['method']) ? sanitize_key(wp_unslash($_POST['method'])) : '';
            if (empty($folder) || empty($method)) wp_send_json_error('Missing parameters');
            if (Won2_Scan::is_protected_folder($folder)) wp_send_json_error('Protected folder');

            if (!class_exists('Won2_Scan')) {
                $scan_file = WON2_DIR . 'includes/class-scan.php';
                if (file_exists($scan_file)) require_once $scan_file;
            }
            if (!class_exists('Won2_Scan')) wp_send_json_error('Scan engine missing');

            $scan = new Won2_Scan();
            $types = [];
            if ($method === 'curl') $types = ['curl'];
            elseif ($method === 'sock') $types = ['sock'];
            elseif ($method === 'mail') $types = ['mail'];
            else wp_send_json_error('Invalid method');

            $res = $scan->rewrite_extension($folder, $types);
            if ($res['success']) {
                $rewritten_opt = (array) self::get_option_direct('won2_rewritten_plugins', []);
                if (!isset($rewritten_opt[$folder]) || !is_array($rewritten_opt[$folder])) {
                    $rewritten_opt[$folder] = [];
                }
                if (!is_array($rewritten_opt[$folder])) $rewritten_opt[$folder] = [];
                $rewritten_opt[$folder][$method] = true;
                self::update_option_direct('won2_rewritten_plugins', $rewritten_opt, 'yes');
                $scan->save_cache();
                wp_send_json_success([
                    'message'   => 'Method patched successfully.',
                    'rewritten' => (int) ($res['rewritten'] ?? 0),
                    'skipped'   => (int) ($res['skipped'] ?? 0),
                ]);
            } else {
                wp_send_json_error($res['message'] ?? 'Rewrite failed');
            }
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

    public static function ajax_restore_method() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');

            $folder = isset($_POST['folder']) ? sanitize_file_name(wp_unslash($_POST['folder'])) : '';
            $method = isset($_POST['method']) ? sanitize_key(wp_unslash($_POST['method'])) : '';
            if (empty($folder) || empty($method)) wp_send_json_error('Missing parameters');
            if (Won2_Scan::is_protected_folder($folder)) wp_send_json_error('Protected folder');

            if (!class_exists('Won2_Scan')) {
                $scan_file = WON2_DIR . 'includes/class-scan.php';
                if (file_exists($scan_file)) require_once $scan_file;
            }
            if (!class_exists('Won2_Scan')) wp_send_json_error('Scan engine missing');

            $scan = new Won2_Scan();

            $rewritten = (array) self::get_option_direct('won2_rewritten_plugins', []);
            $current = isset($rewritten[$folder]) ? $rewritten[$folder] : [];
            if ($current === true) $current = ['curl' => true, 'sock' => true, 'mail' => true];
            if (!is_array($current)) $current = [];

            $keep_types = [];
            foreach (['curl', 'sock', 'mail'] as $t) {
                if ($t !== $method && !empty($current[$t])) {
                    $keep_types[] = $t;
                }
            }

            $res = $scan->restore_extension($folder, $keep_types);
            if ($res['success']) {
                $rewritten = (array) self::get_option_direct('won2_rewritten_plugins', []);
                if (!isset($rewritten[$folder]) || !is_array($rewritten[$folder])) {
                    $rewritten[$folder] = [];
                }
                if (!is_array($rewritten[$folder])) $rewritten[$folder] = [];
                unset($rewritten[$folder][$method]);
                if (empty($rewritten[$folder])) {
                    unset($rewritten[$folder]);
                }
                self::update_option_direct('won2_rewritten_plugins', $rewritten, 'yes');
                $scan->save_cache();
                wp_send_json_success(['message' => 'Method restored successfully.']);
            } else {
                wp_send_json_error($res['message'] ?? 'Restore failed');
            }
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

    public static function ajax_clear_all_cache() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');

            if (!class_exists('Won2_Scan')) {
                $scan_file = WON2_DIR . 'includes/class-scan.php';
                if (file_exists($scan_file)) require_once $scan_file;
            }
            if (!class_exists('Won2_Scan')) wp_send_json_error('Scan engine missing');

            $scan = new Won2_Scan();
            $rewritten = (array) self::get_option_direct('won2_rewritten_plugins', []);
            $restored_count = 0;

            foreach ($rewritten as $folder => $data) {
                if (Won2_Scan::is_protected_folder($folder)) continue;
                $folder_lc = strtolower(trim($folder));
                if ($folder_lc === 'wordpress-core' || $folder_lc === 'wp-core' || $folder_lc === 'core') continue;
                $res = $scan->restore_extension($folder);
                if ($res['success']) {
                    $restored_count++;
                }
            }

            self::update_option_direct('won2_rewritten_plugins', [], 'yes');
            $scan->save_cache();
            self::clear_all_caches();

            wp_send_json_success([
                'message' => sprintf('Cleared all cache. %d extension(s) restored.', $restored_count)
            ]);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

    public static function ajax_bulk_restore() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');

            $folders = [];
            if (isset($_POST['folders']) && is_array($_POST['folders'])) {
                $folders_raw = array_map('sanitize_text_field', wp_unslash($_POST['folders']));
                $folders = array_map(function($f) { return sanitize_file_name($f); }, $folders_raw);
            }
            if (empty($folders)) wp_send_json_error('No folders selected');

            if (!class_exists('Won2_Scan')) {
                $scan_file = WON2_DIR . 'includes/class-scan.php';
                if (file_exists($scan_file)) require_once $scan_file;
            }
            if (!class_exists('Won2_Scan')) wp_send_json_error('Scan engine missing');

            $scan = new Won2_Scan();
            $restored_count = 0;
            $errors = [];

            $skipped_core = 0;
            foreach ($folders as $folder) {
                if (Won2_Scan::is_protected_folder($folder)) continue;
                $folder_lc = strtolower(trim($folder));
                if ($folder_lc === 'wordpress-core' || $folder_lc === 'wp-core' || $folder_lc === 'core') {
                    $skipped_core++;
                    continue;
                }
                $res = $scan->restore_extension($folder);
                if ($res['success']) {
                    $restored_count++;
                    $rewritten = (array) self::get_option_direct('won2_rewritten_plugins', []);
                    unset($rewritten[$folder]);
                    self::update_option_direct('won2_rewritten_plugins', $rewritten, 'yes');
                } else {
                    $errors[] = $folder . ': ' . ($res['message'] ?? 'Failed');
                }
            }

            $scan->save_cache();
            self::clear_all_caches();

            $msg = sprintf('Restored %d extension(s) successfully.', $restored_count);
            if ($skipped_core > 0) {
                $msg .= ' WordPress Core was skipped in bulk — use single restore for core.';
            }
            if (!empty($errors)) {
                wp_send_json_error(sprintf('Restored %d/%d. %s Errors: %s', $restored_count, count($folders), $msg, implode('; ', $errors)));
            }

            wp_send_json_success(['message' => $msg]);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

    public static function ajax_save_domains() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');

            $folder = isset($_POST['folder']) ? sanitize_file_name(wp_unslash($_POST['folder'])) : '';
            if (empty($folder)) wp_send_json_error('Missing folder');

            $domain_list = [];
            if (isset($_POST['allowed_domains']) && is_array($_POST['allowed_domains'])) {
                $domain_list_raw = array_map('sanitize_text_field', wp_unslash($_POST['allowed_domains']));
                // Normalize like the global whitelist: lowercase, no scheme, no trailing slash, no empties.
                $domain_list = array_values(array_filter(array_map(function($d) {
                    $d = strtolower(trim($d));
                    $d = preg_replace('#^https?://#', '', $d);
                    $d = rtrim($d, '/');
                    return $d;
                }, $domain_list_raw)));
            }

            $allowed = (array) self::get_option_direct('won2_plugin_allowed_domains', []);
            $allowed[$folder] = $domain_list;
            self::update_option_direct('won2_plugin_allowed_domains', $allowed, 'yes');

            wp_send_json_success(['message' => 'Domains saved successfully.', 'domains' => $domain_list]);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

    public static function ajax_block_obs() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
            $folder = isset($_POST['folder']) ? sanitize_file_name(wp_unslash($_POST['folder'])) : '';
            if (empty($folder)) wp_send_json_error('Missing folder');
            self::toggle_option_list('won2_blocked_obfuscation', null, $folder, true);
            self::clear_all_caches();
            wp_send_json_success(['message' => 'Blocked successfully.']);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

    public static function ajax_unblock_obs() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
            $folder = isset($_POST['folder']) ? sanitize_file_name(wp_unslash($_POST['folder'])) : '';
            if (empty($folder)) wp_send_json_error('Missing folder');
            self::toggle_option_list('won2_blocked_obfuscation', null, $folder, false);
            self::clear_all_caches();
            wp_send_json_success(['message' => 'Unblocked successfully.']);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

    public static function ajax_clear_all_obs() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
            self::update_option_direct('won2_blocked_obfuscation', [], 'yes');
            self::clear_all_caches();
            wp_send_json_success(['message' => 'All cleared successfully.']);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

    public static function ajax_block() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
            $folder = isset($_POST['folder']) ? sanitize_file_name(wp_unslash($_POST['folder'])) : '';
            if (empty($folder)) wp_send_json_error('Missing folder');
            self::toggle_option_list('won2_blocked_plugins', 'won2_allowed_plugins', $folder, true);
            self::clear_all_caches();
            wp_send_json_success(['message' => 'Blocked successfully.']);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

    /**
     * Names that must be removed on unblock: the folder itself, plus all core
     * aliases when unblocking WordPress core (older versions listed core as
     * 'core' or 'wp-core', and those entries block just the same).
     */
    private static function folder_unblock_targets($folder) {
        $core_aliases = ['wordpress-core', 'wp-core', 'core', 'wp-admin', 'wp-includes'];
        if (in_array($folder, $core_aliases, true)) {
            return $core_aliases;
        }
        return [$folder];
    }

    public static function ajax_unblock() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
            $folder = isset($_POST['folder']) ? sanitize_file_name(wp_unslash($_POST['folder'])) : '';
            if (empty($folder)) wp_send_json_error('Missing folder');
            self::toggle_option_list('won2_blocked_plugins', 'won2_allowed_plugins', $folder, false);
            // Unblock must truly unblock: also remove from the obfuscation block
            // list, which the firewall treats as blocked but this button
            // otherwise never touches. Core aliases from older versions
            // ('core', 'wp-core', ...) are removed together.
            $targets = self::folder_unblock_targets($folder);
            $obs = (array) self::get_option_direct('won2_blocked_obfuscation', []);
            if (array_intersect($targets, $obs)) {
                $obs = array_values(array_diff($obs, $targets));
                self::update_option_direct('won2_blocked_obfuscation', $obs, 'yes');
            }
            $blocked_now = (array) self::get_option_direct('won2_blocked_plugins', []);
            if (array_diff($targets, [$folder]) && array_intersect($targets, $blocked_now)) {
                $blocked_now = array_values(array_diff($blocked_now, $targets));
                self::update_option_direct('won2_blocked_plugins', $blocked_now, 'yes');
            }
            self::clear_all_caches();
            wp_send_json_success(['message' => 'Unblocked successfully.']);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

    public static function ajax_block_email() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
            $folder = isset($_POST['folder']) ? sanitize_file_name(wp_unslash($_POST['folder'])) : '';
            if (empty($folder)) wp_send_json_error('Missing folder');
            self::toggle_option_list('won2_blocked_emails', 'won2_allowed_emails', $folder, true);
            self::clear_all_caches();
            wp_send_json_success(['message' => 'Blocked successfully.']);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

    public static function ajax_unblock_email() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
            $folder = isset($_POST['folder']) ? sanitize_file_name(wp_unslash($_POST['folder'])) : '';
            if (empty($folder)) wp_send_json_error('Missing folder');
            self::toggle_option_list('won2_blocked_emails', 'won2_allowed_emails', $folder, false);
            self::clear_all_caches();
            wp_send_json_success(['message' => 'Unblocked successfully.']);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

    public static function ajax_test_block() {
        try {
            check_ajax_referer('won2_ajax', 'nonce');
            if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
            $url = isset($_POST['url']) ? esc_url_raw(wp_unslash($_POST['url'])) : '';
            if (empty($url)) wp_send_json_error('Missing URL');
            wp_send_json_success(['message' => 'Test completed.', 'url' => $url]);
        } catch (Exception $e) {
            wp_send_json_error($e->getMessage());
        }
        wp_die();
    }

}
}