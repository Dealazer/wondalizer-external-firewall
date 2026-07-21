<?php
/**
 * Wondalizer External Firewall — Render: About, Modal & Footer
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Render_About')) {
class Won2_Render_About {
    public static function output() {
        ?>
<div id="panel-about" class="won2-panel">
                <h2 style="margin-top:24px;">❤️  <?php esc_html_e('About Wondalizer External Firewall', 'wondalizer-external-firewall'); ?></h2>

                <div class="won1-info-box" style="margin-top:20px; border-color:#17a2b8; background:#fff;">
                    <h4 style="margin:0 0 15px 0; font-size:18px; color:#1d2327;">🖥️ <?php esc_html_e('System & Environment Status', 'wondalizer-external-firewall'); ?></h4>
                    <div class="won1-status-grid">
                        <div class="won1-status-card">
                            <h4><?php esc_html_e('PHP Environment', 'wondalizer-external-firewall'); ?></h4>
                            <p><strong>Version:</strong> <?php echo esc_html(PHP_VERSION); ?></p>
                            <p><strong>Memory Limit:</strong> <?php echo esc_html(ini_get('memory_limit')); ?></p>
                            <p><strong>Max Execution Time:</strong> <?php echo esc_html(ini_get('max_execution_time')); ?>s</p>
                        </div>
                        <div class="won1-status-card">
                            <h4><?php esc_html_e('WordPress Engine', 'wondalizer-external-firewall'); ?></h4>
                            <p><strong>Version:</strong> <?php echo esc_html(get_bloginfo('version')); ?></p>
                            <p><strong>WP Memory Limit:</strong> <?php echo esc_html(WP_MEMORY_LIMIT); ?></p>
                            <p><strong>Multisite:</strong> <?php echo esc_html(is_multisite() ? 'Yes' : 'No'); ?></p>
                        </div>
                        <div class="won1-status-card">
                            <h4><?php esc_html_e('Server Extensions', 'wondalizer-external-firewall'); ?></h4>
                            <p><strong>cURL:</strong> <?php echo wp_kses_post(function_exists('curl_version') ? '<span style="color:#28a745;">Enabled</span>' : '<span style="color:#dc3545;">Disabled</span>'); ?></p>
                            <p><strong>Sockets:</strong> <?php echo wp_kses_post(function_exists('fsockopen') ? '<span style="color:#28a745;">Enabled</span>' : '<span style="color:#dc3545;">Disabled</span>'); ?></p>
                            <p><strong>Mail():</strong> <?php echo wp_kses_post(function_exists('mail') ? '<span style="color:#28a745;">Enabled</span>' : '<span style="color:#dc3545;">Disabled</span>'); ?></p>
                        </div>
                        <div class="won1-status-card">
                            <h4><?php esc_html_e('Firewall Protection', 'wondalizer-external-firewall'); ?></h4>
                            <p><strong>HTTP Blocks:</strong> <?php echo (int) count((array) get_option('won2_blocked_plugins', [])); ?> active rules</p>
                            <p><strong>Email Blocks:</strong> <?php echo (int) count((array) get_option('won2_blocked_emails', [])); ?> active rules</p>
                            <p><strong>Malware Blocks:</strong> <?php echo (int) count((array) get_option('won2_blocked_obfuscation', [])); ?> active rules</p>
                        </div>
                    </div>
                </div>

                <div class="won1-info-box" style="border-left-color: #856404; background: #fff3cd;">
                    <p><strong><?php esc_html_e('Important Readme Note:', 'wondalizer-external-firewall'); ?></strong></p>
                    <p><?php esc_html_e('After blocking or unblocking extensions, you may need to clear Opcache, Memcache, Redis, or SQLite cache. Changes are applied at the PHP level but cached files may still execute old code. If you do not see changes immediately, try clearing your server cache or restarting PHP-FPM.', 'wondalizer-external-firewall'); ?></p>
                </div>

                <div style="background:#fff3cd;border:2px solid #ffc107;padding:25px;margin-top:20px;border-radius:4px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                    <h3 style="margin-top:0; font-size:22px; color:#856404;">❤️ <?php esc_html_e('Support This Plugin', 'wondalizer-external-firewall'); ?></h3>
                    <p style="font-size:15px; color:#555;"><?php esc_html_e('If this plugin helps protect your site, consider supporting its development so we can keep updating the detection algorithms.', 'wondalizer-external-firewall'); ?></p>
                    <p style="font-size:18px;font-weight:bold;color:#333;">100€ <?php esc_html_e('or', 'wondalizer-external-firewall'); ?> 500€</p>
                    <p><a href="https://www.paypal.com/donate/?hosted_button_id=XSMXZGDC997UY" target="_blank" class="button button-primary" style="font-size:16px;padding:10px 25px;line-height:1.5;box-shadow:0 3px 6px rgba(0,0,0,0.1);"><?php esc_html_e('Donate with PayPal', 'wondalizer-external-firewall'); ?></a></p>
                </div>
                
                <div style="background:#000;padding:15px 25px;border:2px solid #ba1010;margin-top:20px;border-radius:4px;text-align:center;box-shadow:0 2px 10px rgba(0,0,0,0.15);">
                    <p style="color:#fff;font-weight:bold;font-size:16px;margin:0;">🎵 <?php esc_html_e("Do you want to listen to the creator of this plugin his music? It's hot and wonderful music so go and always visit", 'wondalizer-external-firewall'); ?> <a href="https://wondalizer.com" target="_blank" style="color:#ff4444;text-decoration:underline;font-weight:bold;">wondalizer.com</a></p>
                </div>

                <div style="margin-top:20px;padding:15px;background:#f0f0f0;border-left:4px solid #007cba;border-radius:4px;">
                    <h4 style="margin:0 0 10px 0;">📖 <?php esc_html_e('Important Readme Note', 'wondalizer-external-firewall'); ?></h4>
                    <p style="margin:0;font-size:13px;color:#555;line-height:1.6;">
                        <?php esc_html_e('After blocking or unblocking plugins in the lists, you may need to clear your server cache for changes to take effect immediately. This includes Opcache, Memcache, Redis, or SQLite cache if used by your WordPress installation. The firewall changes are applied at the PHP level, but cached PHP files may still execute the old code until the cache is flushed. For immediate effect, clear all caches after making changes to blocklists or allowlists.', 'wondalizer-external-firewall'); ?>
                    </p>
                </div>

                <div style="background:#fff;padding:20px;border:1px solid #c3c4c7;margin-top:20px;border-radius:4px;">
                    <h3 style="margin-top:0;"><?php esc_html_e('Plugin Information', 'wondalizer-external-firewall'); ?></h3>
                    <table class="form-table">
                        <tr><th><?php esc_html_e('Plugin Name', 'wondalizer-external-firewall'); ?></th><td><strong>Wondalizer External Firewall</strong></td></tr>
                        <tr><th><?php esc_html_e('Version', 'wondalizer-external-firewall'); ?></th><td><?php echo esc_html(WON2_VERSION); ?></td></tr>
                        <tr><th><?php esc_html_e('Plugin URI', 'wondalizer-external-firewall'); ?></th><td><a href="https://psycholatic.com/wondalizer-external-firewall" target="_blank">https://psycholatic.com/wondalizer-external-firewall</a></td></tr>
                        <tr><th><?php esc_html_e('Author', 'wondalizer-external-firewall'); ?></th><td>Wondalizer</td></tr>
                        <tr><th><?php esc_html_e('Author URI', 'wondalizer-external-firewall'); ?></th><td><a href="https://wondalizer.com" target="_blank">https://wondalizer.com</a></td></tr>
                        <tr><th><?php esc_html_e('License', 'wondalizer-external-firewall'); ?></th><td>GPL-2.0+</td></tr>
                    </table>
                </div>

                <div style="background:#f0f6fc;padding:20px;border:1px solid #c5d9ed;margin-top:20px;border-radius:4px;">
                    <h3 style="margin-top:0;"><?php esc_html_e('Core Features', 'wondalizer-external-firewall'); ?></h3>
                    <ul style="list-style:none;margin-left:0;padding-left:0;">
                        <li style="margin-bottom:8px;">✅ <?php esc_html_e('HTTP / cURL Request Firewall with per-plugin control', 'wondalizer-external-firewall'); ?></li>
                        <li style="margin-bottom:8px;">✅ <?php esc_html_e('Email Firewall blocking wp_mail() and mail() independently', 'wondalizer-external-firewall'); ?></li>
                        <li style="margin-bottom:8px;">✅ <?php esc_html_e('cURL Cache Engine — rewrites raw cURL, fsockopen, mail() to WordPress APIs', 'wondalizer-external-firewall'); ?></li>
                        <li style="margin-bottom:8px;">✅ <?php esc_html_e('Obfuscation Detection (Bad Potential) with threat scoring', 'wondalizer-external-firewall'); ?></li>
                        <li style="margin-bottom:8px;">✅ <?php esc_html_e('WordPress Core and Theme specific bulk blocking controls', 'wondalizer-external-firewall'); ?></li>
                        <li style="margin-bottom:8px;">✅ <?php esc_html_e('Custom domain whitelist with WordPress Core auto-whitelist', 'wondalizer-external-firewall'); ?></li>
                        <li style="margin-bottom:8px;">✅ <?php esc_html_e('reCAPTCHA-safe by default', 'wondalizer-external-firewall'); ?></li>
                        <li style="margin-bottom:8px;">✅ <?php esc_html_e('Activity logging with configurable retention', 'wondalizer-external-firewall'); ?></li>
                        <li style="margin-bottom:8px;">✅ <?php esc_html_e('MU helper for early interception', 'wondalizer-external-firewall'); ?></li>
                    </ul>
                </div>
            </div>

            

        <?php
    }
}
}