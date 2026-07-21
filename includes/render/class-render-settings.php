<?php
/**
 * Wondalizer External Firewall — Render: Settings (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Render_Settings')) {
class Won2_Render_Settings {
    public static function output($settings) {
        $logging_on = !empty($settings['logging_enabled']);
        $http_on = !empty($settings['http_firewall_enabled']);
        $cron_on = !empty($settings['cron_firewall_enabled']);
        $curl_on = !empty($settings['curl_cache_enabled']);
        ?>
<div id="panel-settings" class="won2-panel">
    <form method="post" style="max-width:900px;background:#fff;padding:25px;border:1px solid #c3c4c7;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,0.04);">
        <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
        <input type="hidden" name="won2_action" value="save_settings">
        <input type="hidden" name="won1_full_settings_form" value="1">
        <h2 style="margin-top:0;">⚙️ <?php esc_html_e('Firewall Settings', 'wondalizer-external-firewall'); ?></h2>

        <h3 style="border-bottom:1px solid #e0e0e0;padding-bottom:10px;color:#1d2327;"><?php esc_html_e('Explicit Logging Options', 'wondalizer-external-firewall'); ?></h3>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e('Logging Engine', 'wondalizer-external-firewall'); ?></th>
                <td>
                    <label class="won1-toggle">
                        <input type="checkbox" name="settings[logging_enabled]" value="1" <?php checked($logging_on); ?>>
                        <span class="won1-toggle-slider"></span>
                    </label>
                    <p class="description">
                        <?php esc_html_e('Enable or disable the logging engine. When enabled, the plugin logs: HTTP requests (allowed and blocked), email attempts (allowed and blocked), and blocked attempts with source tracing.', 'wondalizer-external-firewall'); ?>
                    </p>
                </td>
            </tr>

            <tr><th><?php esc_html_e('HTTP Logs', 'wondalizer-external-firewall'); ?></th><td>
                <label style="display:block;"><input type="checkbox" name="settings[log_http_blocked]" value="1" <?php checked(!isset($settings['log_http_blocked']) || !empty($settings['log_http_blocked'])); ?>> <?php esc_html_e('Log BLOCKED HTTP requests', 'wondalizer-external-firewall'); ?></label>
                <label style="display:block;margin-top:4px;"><input type="checkbox" name="settings[log_http_allowed]" value="1" <?php checked(!empty($settings['log_http_allowed'])); ?>> <?php esc_html_e('Log ALLOWED HTTP requests (Warning: can be very large)', 'wondalizer-external-firewall'); ?></label>
            </td></tr>
            <tr><th><?php esc_html_e('Email Logs', 'wondalizer-external-firewall'); ?></th><td>
                <label style="display:block;"><input type="checkbox" name="settings[log_email_blocked]" value="1" <?php checked(!isset($settings['log_email_blocked']) || !empty($settings['log_email_blocked'])); ?>> <?php esc_html_e('Log BLOCKED Emails', 'wondalizer-external-firewall'); ?></label>
                <label style="display:block;margin-top:4px;"><input type="checkbox" name="settings[log_email_allowed]" value="1" <?php checked(!isset($settings['log_email_allowed']) || !empty($settings['log_email_allowed'])); ?>> <?php esc_html_e('Log ALLOWED Emails', 'wondalizer-external-firewall'); ?></label>
            </td></tr>
            <tr><th><?php esc_html_e('Internal HTTP', 'wondalizer-external-firewall'); ?></th><td><label><input type="checkbox" name="settings[log_internal_http]" value="1" <?php checked(!empty($settings['log_internal_http'])); ?>> <?php esc_html_e('Also log internal / same-site HTTP requests', 'wondalizer-external-firewall'); ?></label></td></tr>
            <tr><th><?php esc_html_e('cURL Cache Logs', 'wondalizer-external-firewall'); ?></th><td>
                <label><input type="checkbox" name="settings[log_curl_cache]" value="1" <?php checked(!empty($settings['log_curl_cache'])); ?>> <?php esc_html_e('Log all intercepted cURL / socket / mail calls from rewritten plugins', 'wondalizer-external-firewall'); ?></label>
                <p class="description"><?php esc_html_e('When enabled, every call intercepted by the cURL Cache rewrite engine is recorded in the logs. Useful for monitoring plugin behavior after rewrite.', 'wondalizer-external-firewall'); ?></p>
            </td></tr>
            <tr><th><?php esc_html_e('Log Retention', 'wondalizer-external-firewall'); ?></th><td><input type="number" name="settings[retention_days]" value="<?php echo esc_attr($settings['retention_days'] ?? 14); ?>" min="1" max="90" class="small-text"> days</td></tr>
</table>

        <h3 style="border-bottom:1px solid #e0e0e0;padding-bottom:10px;margin-top:40px;color:#1d2327;">🌐 <?php esc_html_e('Domain Controls', 'wondalizer-external-firewall'); ?></h3>
        <table class="form-table">
            <tr><th><?php esc_html_e('Whitelisted Domains', 'wondalizer-external-firewall'); ?></th><td><textarea name="settings[whitelist]" id="won1-whitelist-textarea" rows="6" class="large-text" style="font-family:monospace;"><?php echo esc_textarea(implode("\n", (array) ($settings['whitelist'] ?? []))); ?></textarea><p class="description"><?php esc_html_e('One domain per line. Ex: api.stripe.com. These domains are always allowed — except for plugins you explicitly blocked on the HTTP Firewall page (an explicit block wins over this list). Use the per-plugin Domains button to grant a blocked plugin specific domain exceptions.', 'wondalizer-external-firewall'); ?></p></td></tr>
            <tr><th><?php esc_html_e('WordPress Core', 'wondalizer-external-firewall'); ?></th><td><button type="button" onclick="won1AddDomains(this)" data-domains="wordpress.org|api.wordpress.org|downloads.wordpress.org|planet.wordpress.org|core.trac.wordpress.org|meta.trac.wordpress.org|ps.w.org|s.w.org|wordpress.com|jetpack.wordpress.com|public-api.wordpress.com|stats.wordpress.com" class="button button-primary"><?php esc_html_e('Auto-Whitelist WordPress Core Domains', 'wondalizer-external-firewall'); ?></button></td></tr>
            <tr><th><?php esc_html_e('reCAPTCHA', 'wondalizer-external-firewall'); ?></th><td><button type="button" onclick="won1AddDomains(this)" data-domains="google.com|gstatic.com|recaptcha.net" class="button button-secondary"><?php esc_html_e('Auto-Whitelist reCAPTCHA Domains', 'wondalizer-external-firewall'); ?></button></td></tr>
        </table>

        <h3 style="border-bottom:1px solid #e0e0e0;padding-bottom:10px;margin-top:40px;color:#1d2327;">✅ <?php esc_html_e('Allowed Domains (Blocked Plugin Exceptions)', 'wondalizer-external-firewall'); ?></h3>
        <div class="won1-info-box" style="border-color:#28a745;background:#e8f5e9;color:#155724;">
            <p><?php esc_html_e('Domains listed here are allowed EVEN for blocked plugins. Unlike the whitelist (which allows all plugins), this list only grants access to specific domains while the plugin remains blocked for everything else. Use this to let blocked plugins access critical APIs without fully unblocking them.', 'wondalizer-external-firewall'); ?></p>
        </div>
        <table class="form-table">
            <tr><th><?php esc_html_e('Allowed Domains', 'wondalizer-external-firewall'); ?></th><td><textarea name="settings[allowed_domains]" rows="6" class="large-text" style="font-family:monospace;"><?php echo esc_textarea(implode("\n", (array) ($settings['allowed_domains'] ?? []))); ?></textarea><p class="description"><?php esc_html_e('One domain per line. Example: api.stripe.com, updates.elementor.com. Blocked plugins can still call these domains.', 'wondalizer-external-firewall'); ?></p></td></tr>
        </table>

        <h3 style="border-bottom:1px solid #e0e0e0;padding-bottom:10px;margin-top:40px;color:#1d2327;">&#128683; <?php esc_html_e('Blocked Domains (Blocklist)', 'wondalizer-external-firewall'); ?></h3>
        <div class="won1-info-box" style="border-color:#dc3545;background:#f8d7da;color:#721c24;">
            <p><?php esc_html_e('Domains listed here will be BLOCKED regardless of source plugin. Use this to stop tracking, analytics, or unwanted API calls. One domain per line. Supports wildcards like *.tracker.com', 'wondalizer-external-firewall'); ?></p>
        </div>
        <table class="form-table">
            <tr><th><?php esc_html_e('Blocked Domains', 'wondalizer-external-firewall'); ?></th><td><textarea name="settings[blocked_domains]" rows="6" class="large-text" style="font-family:monospace;"><?php echo esc_textarea(implode("\n", (array) ($settings['blocked_domains'] ?? []))); ?></textarea><p class="description"><?php esc_html_e('One domain per line. Example: rankmath.com, *.analytics.com', 'wondalizer-external-firewall'); ?></p></td></tr>
        </table>

        <h3 style="border-bottom:1px solid #e0e0e0;padding-bottom:10px;margin-top:40px;color:#1d2327;"><?php esc_html_e('reCAPTCHA Protection', 'wondalizer-external-firewall'); ?></h3>
        <div class="won1-info-box"><p><?php esc_html_e('By default, reCAPTCHA requests to Google are ALLOWED so contact forms and logins do not break. Disable this only if you want to block Google/reCAPTCHA explicitly.', 'wondalizer-external-firewall'); ?></p></div>
        <table class="form-table"><tr><th><?php esc_html_e('Block reCAPTCHA', 'wondalizer-external-firewall'); ?></th><td><label><input type="checkbox" name="settings[block_recaptcha]" value="1" <?php checked(!empty($settings['block_recaptcha'])); ?>> <strong><?php esc_html_e('Block Google reCAPTCHA / gstatic requests', 'wondalizer-external-firewall'); ?></strong></label></td></tr></table>

        <h3 style="border-bottom:1px solid #e0e0e0;padding-bottom:10px;margin-top:40px;color:#1d2327;">🏠 <?php esc_html_e('Same-Site Connection Control', 'wondalizer-external-firewall'); ?></h3>
        <div class="won1-info-box" style="border-color:#17a2b8;background:#e7f5ff;">
            <p><strong><?php esc_html_e('Cache Plugin Notice:', 'wondalizer-external-firewall'); ?></strong> <?php esc_html_e('Many cache and optimization plugins (e.g. WP Rocket, W3 Total Cache, LiteSpeed Cache) make same-site HTTP requests to warm caches or generate static files. Disabling same-site exceptions may break these features.', 'wondalizer-external-firewall'); ?></p>
        </div>
        <table class="form-table">
            <tr><th><?php esc_html_e('Allow Same-Site for Blocked', 'wondalizer-external-firewall'); ?></th><td>
                <label><input type="checkbox" name="settings[allow_same_site_for_blocked]" value="1" <?php checked(!isset($settings['allow_same_site_for_blocked']) || !empty($settings['allow_same_site_for_blocked'])); ?>> <strong><?php esc_html_e('Always allow same-site / localhost connections even for blocked plugins', 'wondalizer-external-firewall'); ?></strong></label>
                <p class="description"><?php esc_html_e('When enabled, plugins that are blocked from external HTTP will still be able to connect to your own domain (same-site). This is required for many cache plugins and internal WordPress features. When disabled, blocked plugins are blocked from ALL HTTP including same-site.', 'wondalizer-external-firewall'); ?></p>
            </td></tr>
        </table>

        <h3 style="border-bottom:1px solid #e0e0e0;padding-bottom:10px;margin-top:40px;color:#1d2327;"><?php esc_html_e('Global Blocking Behaviors', 'wondalizer-external-firewall'); ?></h3>
        <table class="form-table">
            <tr><th><?php esc_html_e('Plugin Defaults', 'wondalizer-external-firewall'); ?></th><td>
                <label style="display:block;margin-bottom:5px;"><input type="checkbox" name="settings[block_by_default]" value="1" <?php checked(!empty($settings['block_by_default'])); ?>> <?php esc_html_e('Block ALL new plugins from making HTTP requests.', 'wondalizer-external-firewall'); ?></label>
                <label style="display:block;"><input type="checkbox" name="settings[block_emails_by_default]" value="1" <?php checked(!empty($settings['block_emails_by_default'])); ?>> <?php esc_html_e('Block ALL new plugins from sending Emails.', 'wondalizer-external-firewall'); ?></label>
            </td></tr>
            <tr><th><span style="color:#b32d2e;"><?php esc_html_e('Hard Block Mode', 'wondalizer-external-firewall'); ?></span></th><td>
                <label style="display:block;margin-bottom:5px;"><input type="checkbox" name="settings[hard_block_mode]" value="1" <?php checked(!empty($settings['hard_block_mode'])); ?>> <strong><?php esc_html_e('Hard block EVERY plugin, theme and unknown source that is not on the Allowed list.', 'wondalizer-external-firewall'); ?></strong></label>
                <p class="description"><?php esc_html_e('Default-deny mode: only extensions you explicitly mark as "Allowed" on the HTTP Firewall page can make external HTTP requests. Unknown, unlisted or hijacked plugins are blocked automatically. WordPress core stays allowed, and the same-site exception still applies when enabled below. To let a plugin through, allow it first on the HTTP Firewall page — enable this only when you are ready to allowlist what your site needs.', 'wondalizer-external-firewall'); ?></p>
            </td></tr>
            <tr><th><?php esc_html_e('Theme Defaults', 'wondalizer-external-firewall'); ?></th><td>
                <label style="display:block;margin-bottom:5px;"><input type="checkbox" name="settings[block_themes_by_default]" value="1" <?php checked(!empty($settings['block_themes_by_default'])); ?>> <?php esc_html_e('Block ALL new themes from making HTTP requests.', 'wondalizer-external-firewall'); ?></label>
                <label style="display:block;"><input type="checkbox" name="settings[block_theme_emails_by_default]" value="1" <?php checked(!empty($settings['block_theme_emails_by_default'])); ?>> <?php esc_html_e('Block ALL new themes from sending Emails.', 'wondalizer-external-firewall'); ?></label>
            </td></tr>
        </table>

        <h3 style="border-bottom:1px solid #e0e0e0;padding-bottom:10px;margin-top:40px;color:#1d2327;">🔥 <?php esc_html_e('Firewall Engine Controls', 'wondalizer-external-firewall'); ?></h3>
        <div class="won1-info-box" style="border-color:#007cba;background:#f0f6fc;">
            <p><?php esc_html_e('Enable or disable the firewall engines entirely. When disabled, the firewall will log but not block any requests. This is useful for monitoring without enforcement.', 'wondalizer-external-firewall'); ?></p>
        </div>
        <table class="form-table">
            <tr><th><?php esc_html_e('HTTP Firewall', 'wondalizer-external-firewall'); ?></th><td>
                <label style="display:block;margin-bottom:8px;"><input type="checkbox" name="settings[http_firewall_enabled]" value="1" <?php checked(!empty($settings['http_firewall_enabled'])); ?>> <strong><?php esc_html_e('Enable HTTP Firewall', 'wondalizer-external-firewall'); ?></strong></label>
                <p class="description" style="margin:0;"><?php esc_html_e('When enabled, the firewall actively blocks or allows HTTP requests from plugins and themes based on your roster settings. When disabled, all HTTP requests are allowed (monitoring only).', 'wondalizer-external-firewall'); ?></p>
            </td></tr>
            <tr><th><?php esc_html_e('Cron Firewall', 'wondalizer-external-firewall'); ?></th><td>
                <label style="display:block;margin-bottom:8px;"><input type="checkbox" name="settings[cron_firewall_enabled]" value="1" <?php checked(!empty($settings['cron_firewall_enabled'])); ?>> <strong><?php esc_html_e('Enable Cron Firewall', 'wondalizer-external-firewall'); ?></strong></label>
                <p class="description" style="margin:0;"><?php esc_html_e('When enabled, the firewall blocks cron jobs from blocked plugins and themes. When disabled, all cron jobs run normally regardless of block status.', 'wondalizer-external-firewall'); ?></p>
            </td></tr>
        </table>

        <h3 style="border-bottom:1px solid #e0e0e0;padding-bottom:10px;margin-top:40px;color:#1d2327;"><?php esc_html_e('Commerce & Payment Whitelists', 'wondalizer-external-firewall'); ?></h3>
        <p class="description"><?php esc_html_e('Never block HTTP requests or emails from these trusted commerce plugins.', 'wondalizer-external-firewall'); ?></p>
        <table class="form-table">
            <tr><th><?php esc_html_e('WooCommerce', 'wondalizer-external-firewall'); ?></th><td><label><input type="checkbox" name="settings[whitelist_woocommerce]" value="1" <?php checked(!empty($settings['whitelist_woocommerce'])); ?>> <?php esc_html_e('Always allow WooCommerce emails and HTTP requests (orders, webhooks, API calls).', 'wondalizer-external-firewall'); ?></label></td></tr>
            <tr><th><?php esc_html_e('Easy Digital Downloads', 'wondalizer-external-firewall'); ?></th><td><label><input type="checkbox" name="settings[whitelist_edd]" value="1" <?php checked(!empty($settings['whitelist_edd'])); ?>> <?php esc_html_e('Always allow EDD emails and HTTP requests (purchase receipts, API calls).', 'wondalizer-external-firewall'); ?></label></td></tr>
            <tr><th><?php esc_html_e('PayPal', 'wondalizer-external-firewall'); ?></th><td><label><input type="checkbox" name="settings[whitelist_paypal]" value="1" <?php checked(!empty($settings['whitelist_paypal'])); ?>> <?php esc_html_e('Always allow PayPal emails and HTTP requests (IPN, PDT, API calls, payment confirmations).', 'wondalizer-external-firewall'); ?></label></td></tr>
        </table>

        <h3 style="border-bottom:1px solid #e0e0e0;padding-bottom:10px;margin-top:40px;color:#1d2327;"><?php esc_html_e('cURL & Mail Rewrite Engine', 'wondalizer-external-firewall'); ?></h3>
        <div class="won1-danger-box" style="background:#fff5f5;border:1px solid #fc8181;padding:15px;border-radius:4px;margin-bottom:15px;">
            <h4 style="margin:0 0 10px 0;color:#721c24;">⚠️ <?php esc_html_e('CRITICAL WARNING: File Modification', 'wondalizer-external-firewall'); ?></h4>
            <p style="margin:0;"><?php esc_html_e('Enabling Cache Engine will PHYSICALLY REWRITE plugin/theme PHP files on your server disk.', 'wondalizer-external-firewall'); ?></p>
        </div>
        <table class="form-table">
            <tr><th><?php esc_html_e('Enable Cache Engine', 'wondalizer-external-firewall'); ?></th><td>
                <div style="background:#fff3cd;border:2px solid #ffc107;padding:12px;margin:10px 0;border-radius:4px;"><label><input type="checkbox" name="settings[curl_cache_understood]" value="1" <?php checked(!empty($settings['curl_cache_understood'])); ?>> <?php esc_html_e('I UNDERSTAND that enabling Cache Engine will modify files on disk.', 'wondalizer-external-firewall'); ?></label></div>
                <label style="display:block;margin-top:10px;"><input type="checkbox" name="settings[curl_cache_enabled]" value="1" <?php checked($curl_on); ?>> <strong><?php esc_html_e('Enable Rewrite Engine Master Switch', 'wondalizer-external-firewall'); ?></strong></label>
            </td></tr>
            <tr><th><?php esc_html_e('Granular Rewrites', 'wondalizer-external-firewall'); ?></th><td>
                <label style="display:inline-block;margin-right:15px;"><input type="checkbox" name="settings[rw_curl]" value="1" <?php checked(!empty($settings['rw_curl'])); ?>> <strong>cURL Engine</strong></label>
                <label style="display:inline-block;margin-right:15px;"><input type="checkbox" name="settings[rw_sock]" value="1" <?php checked(!empty($settings['rw_sock'])); ?>> <strong>Socket Engine</strong></label>
                <label style="display:inline-block;"><input type="checkbox" name="settings[rw_mail]" value="1" <?php checked(!empty($settings['rw_mail'])); ?>> <strong>PHP mail()</strong></label>
            </td></tr>
            <tr><th><?php esc_html_e('Auto Rewrite', 'wondalizer-external-firewall'); ?></th><td><label><input type="checkbox" name="settings[auto_rewrite_curl]" value="1" <?php checked(!empty($settings['auto_rewrite_curl'])); ?>> <?php esc_html_e('Automatically rewrite on plugin/theme activation and updates.', 'wondalizer-external-firewall'); ?></label></td></tr>
            <tr><th><?php esc_html_e('Ultimate Scan', 'wondalizer-external-firewall'); ?></th><td>
                <div style="background:#fff3cd;border:2px solid #ffc107;padding:12px;margin:10px 0;border-radius:4px;">
                    <label><input type="checkbox" name="settings[ultimate_scan_enabled]" value="1" <?php checked(!empty($settings['ultimate_scan_enabled'])); ?>> <strong><?php esc_html_e('Enable Ultimate Scan (100% file scan)', 'wondalizer-external-firewall'); ?></strong></label>
                </div>
                <p class="description" style="margin:0;color:#856404;">
                    <?php esc_html_e('WARNING: This will scan ALL files in each plugin (up to 1000 files), including vendor/, tests/, and assets. This takes significantly longer and uses more memory. Only enable if you suspect plugins are using hidden socket/email methods not detected by the standard scan.', 'wondalizer-external-firewall'); ?>
                </p>
                <p class="description" style="margin:4px 0 0 0;color:#856404;">
                    <?php esc_html_e('Standard scan: 50 files per plugin. Ultimate scan: 1000 files per plugin. Be sure you want this — it will take time.', 'wondalizer-external-firewall'); ?>
                </p>
            </td></tr>
        </table>

        <p style="margin-top:30px;">
            <?php submit_button(__('Save Settings', 'wondalizer-external-firewall'), 'primary', 'submit', false); ?>
        </p>
    </form>
</div>
        <?php
    }
}
}