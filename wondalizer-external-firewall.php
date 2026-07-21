<?php
/**
 * Plugin Name: Wondalizer External Firewall
 * Plugin URI:  https://psycholatic.com/wondalizer-external-firewall
 * Description: Advanced external request firewall for WordPress with cURL, socket, and email. Advanced management and intruder prevention for hijacked plugins, plus logging for the curious and the paranoid in all of us.
 * Version:     8.1.8
 * Author:      Wondalizer
 * Author URI:  https://wondalizer.com
 * License:     GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: wondalizer-external-firewall
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) exit;

/**
 * Wondalizer FW Debugger — transient-based logging (no files)
 */


function won2_debug_log($message) {
    if (defined('WP_DEBUG') && WP_DEBUG && defined('WON1_DEBUG') && WON1_DEBUG) {
        $logs = get_transient('won1_debug_logs');
        if (!is_array($logs)) {
            $logs = array();
        }
        $entry = '[' . gmdate('Y-m-d H:i:s') . '] ' . (is_scalar($message) ? $message : (is_array($message) || is_object($message) ? json_encode($message) : (string) $message));
        $logs[] = $entry;
        if (count($logs) > 100) {
            $logs = array_slice($logs, -100);
        }
        set_transient('won1_debug_logs', $logs, HOUR_IN_SECONDS);
    }
}

if (!defined('WPMU_PLUGIN_DIR')) {
    define('WPMU_PLUGIN_DIR', WP_CONTENT_DIR . '/mu-plugins');
}

define('WON2_VERSION', '8.1.8');
define('WON2_DIR', plugin_dir_path(__FILE__));
define('WON2_URL', plugin_dir_url(__FILE__));
define('WON2_SLUG', 'wondalizer-external-firewall');
define('WON2_MU_PATH', WPMU_PLUGIN_DIR . '/wondalizer-fw-curl-guard.php');
define('WON2_ASSETS_URL', WON2_URL . 'assets/');
define('WON2_SELF', 'wondalizer-external-firewall');

$GLOBALS['won2_intercept_buffer'] = array();

add_action('muplugins_loaded', 'won2_early_boot', 1);
function won2_early_boot() {
    won2_debug_log('WON1-EARLY-BOOT: muplugins_loaded fired');
    if (function_exists('get_transient') && isset($GLOBALS['wpdb']) && $GLOBALS['wpdb'] instanceof wpdb) {
        if (!get_transient('won1_early_boot_time')) {
            set_transient('won1_early_boot_time', time(), 60);
        }
    }
}

add_action('plugins_loaded', 'won2_boot', 5);
function won2_boot() {
    $last_boot = get_transient('won1_last_boot_log');
    if (!$last_boot) {
        won2_debug_log('WON1-BOOT: won2_boot() started v' . WON2_VERSION);
        set_transient('won1_last_boot_log', time(), 300);
    }

    $is_admin = is_admin();
    $is_our_ajax = false;
    if (defined('DOING_AJAX') && DOING_AJAX) {
        $action = '';
        if (isset($_REQUEST['action']) && is_string($_REQUEST['action'])) {
            $action = sanitize_key(wp_unslash($_REQUEST['action']));
        }
        $is_our_ajax = (strpos($action, 'won2_') === 0);
        if ($is_our_ajax) {
            if (!isset($_REQUEST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_REQUEST['nonce'])), 'won2_ajax')) {
                $is_our_ajax = false;
            }
        }
    }

    won2_ensure_mu_guard();
    won2_migrate_options();

    $files = array('includes/class-logger.php', 'includes/class-source.php', 'includes/class-firewall.php', 'includes/class-guard.php', 'wondalizer-fw-curl-guard.php');
    foreach ($files as $f) {
        $p = WON2_DIR . $f;
        if (file_exists($p)) require_once $p;
    }

    if (class_exists('Won2_Logger')) {
        try {
            $logger = Won2_Logger::init();
            $logger->ensure_table();
            if (!$last_boot) $logger->trace('BOOT: Logger initialized v' . WON2_VERSION);
        } catch (\Throwable $e) {
            won2_debug_log('WON1-BOOT-ERROR: Logger init failed: ' . $e->getMessage());
        }
    }

    if (class_exists('Won2_Firewall')) {
        try {
            $fw = Won2_Firewall::init();
            $fw->start_interception();
            if (!$last_boot) won2_debug_log('WON1-BOOT: Firewall interception started');
        } catch (\Throwable $e) {
            won2_debug_log('WON1-BOOT-ERROR: Firewall start failed: ' . $e->getMessage());
        }
    }

    if ($is_admin && (!defined('DOING_AJAX') || !DOING_AJAX || $is_our_ajax)) {
        $admin_files = array('class-admin-init.php', 'class-admin-render.php', 'class-admin-actions.php',
                             'class-admin-ajax.php', 'class-admin-tables.php', 'class-admin-roster.php', 'class-scan.php');
        foreach ($admin_files as $af) {
            $p = WON2_DIR . 'includes/' . $af;
            if (file_exists($p)) require_once $p;
        }

        $render_files = array('class-render-header.php', 'class-render-roster.php', 'class-render-cron.php',
                                'class-render-settings.php', 'class-render-logs.php', 'class-render-about.php',
                                'class-render-footer.php');
        foreach ($render_files as $rf) {
            $p = WON2_DIR . 'includes/render/' . $rf;
            if (file_exists($p)) require_once $p;
        }
        if (class_exists('Won2_Admin_Init')) {
            try { Won2_Admin_Init::init(null); }
            catch (\Throwable $e) { won2_debug_log('WON1-BOOT-ERROR: Admin init failed: ' . $e->getMessage()); }
        }
        if (class_exists('Won2_Admin_Actions')) {
            try { Won2_Admin_Actions::init(); }
            catch (\Throwable $e) { won2_debug_log('WON1-BOOT-ERROR: Admin Actions init failed: ' . $e->getMessage()); }
        }
        if (class_exists('Won2_Admin_Ajax')) {
            try { Won2_Admin_Ajax::init(); }
            catch (\Throwable $e) { won2_debug_log('WON1-BOOT-ERROR: Admin AJAX init failed: ' . $e->getMessage()); }
        }
    }
}

function won2_ensure_mu_guard() {
    // MU-plugin copy removed per WordPress.org guidelines.
    // The cURL guard is loaded directly by the main plugin.
    return true;
}

/**
 * Migrate legacy option names to the new won1_/won2_ prefixes.
 * Also merges the old, incorrect option names that some AJAX handlers
 * and the standalone guard used to write to, so previously-set blocks
 * finally take effect.
 */
function won2_migrate_options() {
    if (get_option('won2_options_migrated_v810')) {
        return;
    }

    // Canonical renames: old name => new name.
    $renames = array(
        'wondalizer_firewall_settings'      => 'won2_firewall_settings',
        'wondalizer_blocked_plugins'        => 'won2_blocked_plugins',
        'wondalizer_allowed_plugins'        => 'won2_allowed_plugins',
        'wondalizer_blocked_emails'         => 'won2_blocked_emails',
        'wondalizer_allowed_emails'         => 'won2_allowed_emails',
        'wondalizer_blocked_obfuscation'    => 'won2_blocked_obfuscation',
        'wondalizer_rewritten_plugins'      => 'won2_rewritten_plugins',
        'wondalizer_plugin_allowed_domains' => 'won2_plugin_allowed_domains',
        'wondalizer_blocked_cron_hooks'     => 'won2_blocked_cron_hooks',
        'wondalizer_allowed_cron_hooks'     => 'won2_allowed_cron_hooks',
        'wondalizer_scan_cache_v2'          => 'won2_scan_cache_v2',
        'wfw_whitelist_domains'             => 'won1_whitelist_domains',
        'wfw_blacklist_domains'             => 'won1_blacklist_domains',
        'wfw_has_blocks'                    => 'won1_has_blocks',
        'wfw_live_captures'                 => 'won1_live_captures',
        'wfw_intercept_buffer'              => 'won1_intercept_buffer',
    );
    foreach ($renames as $old => $new) {
        $old_val = get_option($old, null);
        if ($old_val === null) {
            continue;
        }
        if (get_option($new, null) === null) {
            add_option($new, $old_val, '', 'yes');
        }
        delete_option($old);
    }

    // Merge historically wrong option names into the canonical ones.
    $merges = array(
        'wondalizer_fw_settings'              => 'won2_firewall_settings',
        'wondalizer_fw_blocked'               => 'won2_blocked_plugins',
        'wondalizer_fw_blocked_plugins'       => 'won2_blocked_plugins',
        'wondalizer_fw_allowed_plugins'       => 'won2_allowed_plugins',
        'wondalizer_fw_blocked_email'         => 'won2_blocked_emails',
        'wondalizer_fw_blocked_emails'        => 'won2_blocked_emails',
        'wondalizer_fw_allowed_emails'        => 'won2_allowed_emails',
        'wondalizer_fw_blocked_obs'           => 'won2_blocked_obfuscation',
        'wondalizer_fw_blocked_obfuscation'   => 'won2_blocked_obfuscation',
        'wondalizer_whitelist_domains'        => 'won1_whitelist_domains',
        'wondalizer_blacklist_domains'        => 'won1_blacklist_domains',
    );
    foreach ($merges as $old => $new) {
        $old_val = get_option($old, null);
        if ($old_val === null) {
            continue;
        }
        $new_val = get_option($new, null);
        if (is_array($old_val) && is_array($new_val)) {
            $merged = array_merge($new_val, $old_val);
            // Associative arrays (settings) vs list arrays (block lists).
            $is_assoc = (array_keys($merged) !== range(0, count($merged) - 1));
            if ($is_assoc) {
                update_option($new, $merged, 'yes');
            } else {
                update_option($new, array_values(array_unique($merged)), 'yes');
            }
        } elseif ($new_val === null) {
            add_option($new, $old_val, '', 'yes');
        }
        delete_option($old);
    }

    // Rename the logs table if it still uses the old prefix.
    global $wpdb;
    if (isset($wpdb) && $wpdb instanceof wpdb) {
        $old_table = $wpdb->prefix . 'wondalizer_fw_logs';
        $new_table = $wpdb->prefix . 'won2_logs';
        if ($old_table !== $new_table) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- one-time schema migration; result is not cacheable
            $old_exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $old_table));
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- one-time schema migration; result is not cacheable
            $new_exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $new_table));
            if ($old_exists && !$new_exists) {
                // Table identifiers are safely quoted via the %i placeholder (WP 6.2+; plugin requires 6.4).
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- one-time table rename during option migration
                $wpdb->query($wpdb->prepare('RENAME TABLE %i TO %i', $old_table, $new_table));
            }
        }
    }

    if (get_option('won2_first_installed') === false) {
        add_option('won2_first_installed', time(), '', 'no');
    }

    add_option('won2_options_migrated_v810', 1, '', 'no');
}

/**
 * One-time donation notices: shown once after 1 week and once after
 * 2 weeks of usage. Each notice marks itself as shown when rendered, so
 * it disappears on the next page load without requiring a manual dismiss
 * (a dismiss button is provided anyway).
 */
add_action('admin_notices', 'won2_donation_notice');
function won2_donation_notice() {
    if (!current_user_can('manage_options')) {
        return;
    }
    $installed = (int) get_option('won2_first_installed', 0);
    if ($installed <= 0) {
        add_option('won2_first_installed', time(), '', 'no');
        return;
    }
    $age = time() - $installed;
    $notice = '';
    if ($age >= 2 * WEEK_IN_SECONDS && !get_option('won2_donate_notice2_shown')) {
        $notice = 'won2_donate_notice2_shown';
    } elseif ($age >= WEEK_IN_SECONDS && !get_option('won2_donate_notice1_shown')) {
        $notice = 'won2_donate_notice1_shown';
    }
    if ($notice === '') {
        return;
    }
    // Mark as shown immediately: the notice removes itself after this page load.
    add_option($notice, 1, '', 'no');
    $about_url = admin_url('admin.php?page=wondalizer-external-firewall#about');
    echo '<div class="notice notice-info is-dismissible"><p>';
    echo esc_html__("We've noticed you used Wondalizer External Firewall more than we expected, if you really like this product, visit the about page to donate, thanks.", 'wondalizer-external-firewall');
    echo ' <a href="' . esc_url($about_url) . '">' . esc_html__('Open the About page', 'wondalizer-external-firewall') . '</a>';
    echo '</p></div>';
}

register_activation_hook(__FILE__, 'won2_activate');
register_deactivation_hook(__FILE__, 'won2_deactivate');

function won2_activate() {
    won2_migrate_options();
    if (get_option('won2_first_installed') === false) {
        add_option('won2_first_installed', time(), '', 'no');
    }
    if (get_option('won1_has_blocks') === false) {
        add_option('won1_has_blocks', 1, '', 'yes');
    } else {
        update_option('won1_has_blocks', 1, 'yes');
    }

    $options_to_init = array(
        'won2_blocked_plugins' => array(),
        'won2_allowed_plugins' => array(),
        'won2_blocked_emails' => array(),
        'won2_allowed_emails' => array(),
        'won2_blocked_obfuscation' => array(),
        'won2_rewritten_plugins' => array(),
        'won2_plugin_allowed_domains' => array(),
        'won1_whitelist_domains' => array(),
        'won1_blacklist_domains' => array()
    );
    foreach ($options_to_init as $opt => $def) {
        if (get_option($opt) === false) {
            add_option($opt, $def, '', 'yes');
        } else {
            update_option($opt, get_option($opt), 'yes');
        }
    }

    $settings = get_option('won2_firewall_settings', array());
    if (!is_array($settings)) $settings = array();
    $defaults = array(
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
        'ultimate_scan_enabled' => false,
    );
    foreach ($defaults as $k => $v) {
        if (!isset($settings[$k])) $settings[$k] = $v;
    }
    if (get_option('won2_firewall_settings') === false) {
        add_option('won2_firewall_settings', $settings, '', 'yes');
    } else {
        update_option('won2_firewall_settings', $settings, 'yes');
    }

    if (get_option('won1_live_captures') === false) {
        add_option('won1_live_captures', array(), '', 'no');
    } else {
        update_option('won1_live_captures', array(), 'no');
    }

    $logger_file = WON2_DIR . 'includes/class-logger.php';
    if (file_exists($logger_file)) {
        require_once $logger_file;
        if (class_exists('Won2_Logger')) {
            $logger = Won2_Logger::init();
            $table_ok = $logger->ensure_table();
            if ($table_ok) {
                $logger->log_direct(
                    'Plugin activated — logger test',
                    'localhost',
                    'ACTIVATE',
                    false,
                    'plugin_activated',
                    array('type'=>'plugin','name'=>'Wondalizer External Firewall','folder'=>'wondalizer-external-firewall','file'=>''),
                    false
                );
            }
        }
    }
}

function won2_deactivate() {
    wp_clear_scheduled_hook('won2_cleanup');
    // Clear scheduled cron jobs
    $timestamp = wp_next_scheduled('won2_cron_firewall');
    if ($timestamp) {
        wp_unschedule_event($timestamp, 'won2_cron_firewall');
    }
}

add_action('won2_cleanup', 'won2_do_cleanup');
function won2_do_cleanup() {
    if (class_exists('Won2_Logger')) {
        Won2_Logger::init()->cleanup();
    }
}
if (!wp_next_scheduled('won2_cleanup')) {
    wp_schedule_event(time(), 'daily', 'won2_cleanup');
}

add_action('shutdown', 'won2_shutdown_flush', 999);
function won2_shutdown_flush() {
    global $won2_intercept_buffer;
    if (empty($won2_intercept_buffer) || !is_array($won2_intercept_buffer)) return;

    $existing = get_option('won1_intercept_buffer', array());
    if (!is_array($existing)) $existing = array();
    $merged = array_merge($existing, $won2_intercept_buffer);
    if (count($merged) > 200) $merged = array_slice($merged, -200);
    if (get_option('won1_intercept_buffer') === false) {
        add_option('won1_intercept_buffer', $merged, '', 'no');
    } else {
        update_option('won1_intercept_buffer', $merged, 'no');
    }

    $live = get_option('won1_live_captures', array());
    if (!is_array($live)) $live = array();
    $live = array_merge($live, $won2_intercept_buffer);
    if (count($live) > 100) $live = array_slice($live, -100);
    update_option('won1_live_captures', $live, false);
}
