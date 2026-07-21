<?php
/**
 * Wondalizer External Firewall — Render: Header & Navigation (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Render_Header')) {
class Won2_Render_Header {
    public static function output($settings, $total_http, $total_http_blocked, $total_email, $total_email_blocked, $total_obs, $http_on, $cron_on, $logging_on, $curl_on, $http_fw_on, $error_msg = '') {
        $msg = '';
        if (isset($_GET['msg']) && isset($_GET['won1_msg_nonce']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['won1_msg_nonce'])), 'won1_msg_action')) {
            $msg = sanitize_key(wp_unslash($_GET['msg']));
        }
        ?>

        <div class="wrap won2-wrap">
            <?php if ($msg === 'updated'): ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('Settings saved successfully.', 'wondalizer-external-firewall'); ?></p></div>
            <?php elseif ($msg === 'logs_cleared'): ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('All logs have been cleared.', 'wondalizer-external-firewall'); ?></p></div>
            <?php endif; ?>

            <?php // All page CSS/JS is enqueued via assets/admin.css and assets/admin.js (no inline output here). ?>

            <h1 style="margin-bottom:20px; font-weight:600; color:#1d2327;">
                <span class="dashicons dashicons-shield" style="font-size:28px; width:28px; height:28px; margin-right:8px; color:#2271b1; vertical-align:middle;"></span>
                <?php esc_html_e('Wondalizer External Firewall', 'wondalizer-external-firewall'); ?>
            </h1>

            <?php if (get_transient('won1_roster_incomplete')): ?>
                <div class="notice notice-warning is-dismissible">
                    <p><strong><?php esc_html_e('Scan Paused for Stability:', 'wondalizer-external-firewall'); ?></strong> <?php esc_html_e('Your site has many extensions. The scanner was paused to prevent timeout. Use "Rescan All Extensions" or just reload the page to continue scanning.', 'wondalizer-external-firewall'); ?></p>
                </div>
            <?php endif; ?>

            <?php if ($error_msg): ?>
                <div class="notice notice-error">
                    <p><strong><?php esc_html_e('Warning:', 'wondalizer-external-firewall'); ?></strong> <?php echo esc_html($error_msg); ?></p>
                </div>
            <?php endif; ?>

            <div class="won1-stats" style="display:flex; gap:15px; flex-wrap:wrap; margin-bottom:25px;">
                <div class="won1-statbox"><h3><?php echo (int)$total_http; ?></h3><p><?php esc_html_e('HTTP Logs (30d)', 'wondalizer-external-firewall'); ?></p></div>
                <div class="won1-statbox" style="border-left:4px solid #dc3545;"><h3 style="color:#dc3545;"><?php echo (int)$total_http_blocked; ?></h3><p><?php esc_html_e('HTTP Blocked', 'wondalizer-external-firewall'); ?></p></div>
                <div class="won1-statbox" style="border-left:4px solid #5b21b6;"><h3><?php echo (int)$total_email; ?></h3><p><?php esc_html_e('Email Logs (30d)', 'wondalizer-external-firewall'); ?></p></div>
                <div class="won1-statbox" style="border-left:4px solid #5b21b6;"><h3 style="color:#dc3545;"><?php echo (int)$total_email_blocked; ?></h3><p><?php esc_html_e('Emails Blocked', 'wondalizer-external-firewall'); ?></p></div>
                <div class="won1-statbox" style="border-left:4px solid #dc3545;"><h3 style="color:<?php echo $total_obs ? '#dc3545' : '#28a745'; ?>;"><?php echo (int)$total_obs; ?></h3><p><?php esc_html_e('Bad Potential', 'wondalizer-external-firewall'); ?></p></div>
                <div class="won1-statbox"><h3 style="color:<?php echo $logging_on ? '#28a745' : '#dc3545'; ?>;"><?php echo $logging_on ? esc_html__('ON', 'wondalizer-external-firewall') : esc_html__('OFF', 'wondalizer-external-firewall'); ?></h3><p><?php esc_html_e('Logging Status', 'wondalizer-external-firewall'); ?></p></div>
            </div>

            <h2 class="nav-tab-wrapper">
                <a href="#roster" class="nav-tab" onclick="showTab('roster');return false;">&#127760; <?php esc_html_e('HTTP Firewall', 'wondalizer-external-firewall'); ?></a>
                <a href="#emails" class="nav-tab" onclick="showTab('emails');return false;">&#9993; <?php esc_html_e('Email Control', 'wondalizer-external-firewall'); ?></a>
                <a href="#curl" class="nav-tab" onclick="showTab('curl');return false;">&#128295; <?php esc_html_e('cURL Cache', 'wondalizer-external-firewall'); ?></a>
                <a href="#risky" class="nav-tab" onclick="showTab('risky');return false;">&#9760; <?php esc_html_e('Bad Potential', 'wondalizer-external-firewall'); ?></a>
                <a href="#cron" class="nav-tab" onclick="showTab('cron');return false;">&#9200; <?php esc_html_e('Cron Firewall', 'wondalizer-external-firewall'); ?></a>
                <a href="#settings" class="nav-tab" onclick="showTab('settings');return false;">&#9881; <?php esc_html_e('Settings', 'wondalizer-external-firewall'); ?></a>
                <a href="#logs" class="nav-tab" onclick="showTab('logs');return false;">&#128196; <?php esc_html_e('Logs', 'wondalizer-external-firewall'); ?></a>
                <a href="#about" class="nav-tab" onclick="showTab('about');return false;">❤️ <?php esc_html_e('About', 'wondalizer-external-firewall'); ?></a>
            </h2>
        <?php
    }
}
}