<?php
/**
 * Wondalizer External Firewall — Render: Roster, Emails, cURL, Risky
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Render_Roster')) {
class Won2_Render_Roster {
    public static function output($roster, $core, $themes, $regular, $settings, $can_rewrite, $log_counts, $error_msg) {
        $http_fw_on = !empty($settings['http_firewall_enabled']);
        $curl_on = !empty($settings['curl_cache_enabled']);
        $total_obs = 0;
        foreach ($roster as $p) {
            if (!empty($p['has_obfuscated'])) {
                $total_obs++;
            }
        }
        $obs_items = array_filter($roster, function($p){ return !empty($p['has_obfuscated']); });
        ?>
<div id="panel-roster" class="won2-panel won1-panel-active">
                <div class="won1-info-box"><h4 style="margin:0 0 5px 0;">🌐 <?php esc_html_e('HTTP / cURL Request Firewall', 'wondalizer-external-firewall'); ?></h4><p style="margin:0;"><?php esc_html_e('Controls whether plugins and themes can make external HTTP connections. Blocks are absolute and happen before DNS resolution.', 'wondalizer-external-firewall'); ?></p></div>

                <div style="background:<?php echo $http_fw_on ? '#d4edda' : '#fff3cd'; ?>;border:1px solid <?php echo $http_fw_on ? '#28a745' : '#ffc107'; ?>;border-radius:4px;padding:15px;margin:15px 0;display:flex;align-items:center;justify-content:space-between;">
                    <div>
                        <h3 style="margin:0 0 5px 0;color:<?php echo $http_fw_on ? '#155724' : '#856404'; ?>;">
                            <?php echo $http_fw_on ? '&#128308; ' . esc_html__('HTTP Firewall is ON — Blocking Mode', 'wondalizer-external-firewall') : '&#128308; ' . esc_html__('HTTP Firewall is OFF — Allow Mode', 'wondalizer-external-firewall'); ?>
                        </h3>
                        <p style="margin:0;color:<?php echo $http_fw_on ? '#155724' : '#856404'; ?>">
                            <?php if ($http_fw_on) { esc_html_e('Default: DENY. Only explicitly unblocked plugins can connect, or allowed domains when blocked.', 'wondalizer-external-firewall'); } else { esc_html_e('Default: ALLOW. Only plugins in the block list and domains in the blocklist are stopped.', 'wondalizer-external-firewall'); } ?>
                        </p>
                    </div>
                    <form method="post" style="display:inline;">
                        <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
                        <input type="hidden" name="won2_action" value="save_settings">
                        <input type="hidden" name="settings[http_firewall_enabled]" value="<?php echo $http_fw_on ? '0' : '1'; ?>">
                        <button type="submit" class="button <?php echo $http_fw_on ? 'button-secondary' : 'button-primary'; ?>" style="font-size:14px;padding:8px 20px;">
                            <?php echo $http_fw_on ? esc_html__('Turn OFF Firewall', 'wondalizer-external-firewall') : esc_html__('Turn ON Firewall', 'wondalizer-external-firewall'); ?>
                        </button>
                    </form>
                </div>
                
                <div class="won1-bulk-bar">
                    <form method="post" style="display:inline;">
                        <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
                        <input type="hidden" name="won2_action" value="rescan">
                        <button type="submit" class="button button-secondary">🔄 <?php esc_html_e('Rescan All Extensions', 'wondalizer-external-firewall'); ?></button>
                    </form>
                    <span style="color:#ccc;margin:0 5px;">|</span>
                    <?php Won2_Admin_Render::bulk_btn('block_all', 'danger', __('🔒 Block ALL Plugin HTTP', 'wondalizer-external-firewall')); ?>
                    <?php Won2_Admin_Render::bulk_btn('unblock_all', 'success', __('🔓 Unblock ALL HTTP', 'wondalizer-external-firewall')); ?>
                    <?php Won2_Admin_Render::bulk_btn('block_core_http', 'danger', __('🔒 Block Core HTTP', 'wondalizer-external-firewall')); ?>
                    <?php Won2_Admin_Render::bulk_btn('unblock_core_http', 'success', __('🔓 Unblock Core HTTP', 'wondalizer-external-firewall')); ?>
                    <?php Won2_Admin_Render::bulk_btn('block_themes_http', 'danger', __('🔒 Block Themes HTTP', 'wondalizer-external-firewall')); ?>
                    <?php Won2_Admin_Render::bulk_btn('unblock_themes_http', 'success', __('🔓 Unblock Themes HTTP', 'wondalizer-external-firewall')); ?>
                    <span style="color:#ccc;margin:0 5px;">|</span>
                    <form method="post" id="bulk-form-http" style="display:inline;">
                        <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
                        <input type="hidden" name="won2_action" id="bulk-action-http" value="block">
                        <input type="hidden" name="selected_plugins" id="bulk-selected-http" value="">
                        <button type="submit" class="button won1-btn warning" onclick="return doBulkAction('http','block');"><?php esc_html_e('🔒 Block Selected', 'wondalizer-external-firewall'); ?></button>
                        <button type="submit" class="button won1-btn" onclick="return doBulkAction('http','unblock');"><?php esc_html_e('🔓 Unblock Selected', 'wondalizer-external-firewall'); ?></button>
                    </form>
                </div>
                <?php Won2_Admin_Tables::render_roster_table($core, 'core', 'section-http-core', ($log_counts['http'] ?? []), 'roster'); ?>
                <?php Won2_Admin_Tables::render_roster_table($themes, 'theme', 'section-http-themes', ($log_counts['http'] ?? []), 'roster'); ?>
                <?php Won2_Admin_Tables::render_roster_table($regular, 'regular', 'section-http-regular', ($log_counts['http'] ?? []), 'roster'); ?>
            </div>

            <div id="panel-emails" class="won2-panel">
                <div class="won1-info-box" style="border-color:#d8b4fe;background:#f3e8ff;color:#4c1d95;"><h4 style="margin:0 0 5px 0;">✉️ <?php esc_html_e('Dedicated Email Firewall', 'wondalizer-external-firewall'); ?></h4><p style="margin:0;"><?php esc_html_e('Independently aborts outbound emails sent by extensions. Protects against spam relays and malicious contact form exploitation.', 'wondalizer-external-firewall'); ?></p></div>
                <div class="won1-bulk-bar">
                    <?php Won2_Admin_Render::bulk_btn('block_all_emails', 'danger', __('🔒 Block ALL Plugin Emails', 'wondalizer-external-firewall'), 'emails'); ?>
                    <?php Won2_Admin_Render::bulk_btn('unblock_all_emails', 'success', __('🔓 Unblock ALL Emails', 'wondalizer-external-firewall'), 'emails'); ?>
                    <?php Won2_Admin_Render::bulk_btn('block_core_emails', 'danger', __('🔒 Block Core Emails', 'wondalizer-external-firewall'), 'emails'); ?>
                    <?php Won2_Admin_Render::bulk_btn('unblock_core_emails', 'success', __('🔓 Unblock Core Emails', 'wondalizer-external-firewall'), 'emails'); ?>
                    <?php Won2_Admin_Render::bulk_btn('block_themes_emails', 'danger', __('🔒 Block Themes Emails', 'wondalizer-external-firewall'), 'emails'); ?>
                    <?php Won2_Admin_Render::bulk_btn('unblock_themes_emails', 'success', __('🔓 Unblock Themes Emails', 'wondalizer-external-firewall'), 'emails'); ?>
                    <span style="color:#ccc;margin:0 5px;">|</span>
                    <form method="post" id="bulk-form-email" style="display:inline;">
                        <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
                        <input type="hidden" name="won2_action" id="bulk-action-email" value="block_email">
                        <input type="hidden" name="won1_tab" value="emails">
                        <input type="hidden" name="selected_plugins" id="bulk-selected-email" value="">
                        <button type="submit" class="button won1-btn warning" onclick="return doBulkAction('email','block_email');"><?php esc_html_e('🔒 Block Selected Emails', 'wondalizer-external-firewall'); ?></button>
                        <button type="submit" class="button won1-btn" onclick="return doBulkAction('email','unblock_email');"><?php esc_html_e('🔓 Unblock Selected Emails', 'wondalizer-external-firewall'); ?></button>
                    </form>
                </div>
                <?php Won2_Admin_Tables::render_email_table($core, 'section-email-core', ($log_counts['email'] ?? []), 'emails'); ?>
                <?php Won2_Admin_Tables::render_email_table($themes, 'section-email-themes', ($log_counts['email'] ?? []), 'emails'); ?>
                <?php Won2_Admin_Tables::render_email_table($regular, 'section-email-regular', ($log_counts['email'] ?? []), 'emails'); ?>
            </div>

            <div id="panel-curl" class="won2-panel">
                <div style="height:15px;"></div>
                <h2 style="margin-top:0;">🔧 <?php esc_html_e('cURL & Mail Rewrite Cache', 'wondalizer-external-firewall'); ?></h2>
                
                <?php if (!defined('WON2_MU_ACTIVE')): ?>
                <div class="won1-danger-box">
                    <h4>⚠️ <?php esc_html_e('MU Plugin Missing or Inactive', 'wondalizer-external-firewall'); ?></h4>
                    <p><?php esc_html_e('The Cache Engine MUST have the Wondalizer MU Plugin active to safely route intercepted calls. To prevent 503 Service Unavailable errors, rewriting is completely disabled until wp-content/mu-plugins is writable and the guard is running.', 'wondalizer-external-firewall'); ?></p>
                </div>
                <?php endif; ?>

                <?php if (!$curl_on): ?>
                <div class="won1-danger-box"><h4>⚠️ <?php esc_html_e('cURL Cache is DISABLED', 'wondalizer-external-firewall'); ?></h4><p><?php esc_html_e('Extensions using raw cURL, fsockopen, or mail() bypass WordPress APIs. Enable cURL Cache in Settings to intercept these safely.', 'wondalizer-external-firewall'); ?></p><p><a href="#settings" class="button button-primary" onclick="showTab('settings');return false;">⚙️ <?php esc_html_e('Go to Settings', 'wondalizer-external-firewall'); ?></a></p></div>
                <?php elseif (defined('WON2_MU_ACTIVE')): ?>
                <div class="won1-info-box" style="border-color:#28a745;background:#d4edda;color:#155724;"><h4>✅ <?php esc_html_e('cURL Cache is ENABLED', 'wondalizer-external-firewall'); ?></h4><p><?php esc_html_e('The firewall is dynamically rewriting raw cURL, sockets, and native mail calls. Original files are backed up automatically as .wondalizer-bak.', 'wondalizer-external-firewall'); ?></p></div>
                <?php endif; ?>
                
                <div class="won1-bulk-bar" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
                    <form method="post" style="display:inline;">
                        <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
                        <input type="hidden" name="won2_action" value="rescan">
                        <input type="hidden" name="won1_tab" value="curl">
                        <button type="submit" class="button button-secondary">🔄 <?php esc_html_e('Rescan All Extensions', 'wondalizer-external-firewall'); ?></button>
                    </form>
                    <button type="button" class="button button-primary" onclick="patchAllExtensions();" <?php disabled(!$can_rewrite); ?>>⚡ <?php esc_html_e('Patch All Eligible Extensions', 'wondalizer-external-firewall'); ?></button>
                    <button type="button" class="button won1-btn danger" onclick="clearAllCache();">🧹 <?php esc_html_e('Clear ALL cURL Cache', 'wondalizer-external-firewall'); ?></button>
                    <button type="button" class="button won1-btn warning" onclick="bulkRestoreSelected();">♻️ <?php esc_html_e('Restore Selected', 'wondalizer-external-firewall'); ?></button>
                    <span id="bulk-cache-spinner" class="spinner" style="float:none;margin-top:0;"></span>
                </div>
                <p class="description" id="bulk-cache-status"><?php esc_html_e('Patch All sequentially processes all unpatched plugins. Select rows and use Restore Selected to bulk-revert.', 'wondalizer-external-firewall'); ?></p>
                <?php
                // Separate items by category for better organization
                $curl_core = array_filter($roster, function($p) { return $p['type'] === 'core'; });
                $curl_mu = array_filter($roster, function($p) { return $p['type'] === 'mu-plugin'; });
                $curl_themes = array_filter($roster, function($p) { return $p['type'] === 'theme'; });
                $curl_plugins = array_filter($roster, function($p) { return $p['type'] === 'plugin'; });

                // Force-display Wondalizer as a protected entry in cURL rewrite — cannot be rewritten
                $won2_curl_entry = [
                    'name'              => 'Wondalizer External Firewall',
                    'folder'            => 'wondalizer-external-firewall',
                    'type'              => 'plugin',
                    'is_curl_protected' => true,
                    'has_curl'          => false,
                    'has_fsockopen'     => false,
                    'has_php_mail'      => false,
                    'has_wp_mail'       => false,
                    'has_phpmailer'     => false,
                    'has_smtp_class'    => false,
                    'has_swiftmailer'   => false,
                    'has_socket_raw'    => false,
                    'has_stream_socket' => false,
                    'has_wp_http'       => false,
                    'rewritten'         => false,
                ];
                $curl_plugins = array_values($curl_plugins);
                array_unshift($curl_plugins, $won2_curl_entry);

                Won2_Admin_Render::won1_render_curl_section($curl_core, 'Core Files', 'curl-core-body');
                Won2_Admin_Render::won1_render_curl_section($curl_mu, 'MU-Plugins', 'curl-mu-body');
                Won2_Admin_Render::won1_render_curl_section($curl_themes, 'Themes', 'curl-themes-body');
                Won2_Admin_Render::won1_render_curl_section($curl_plugins, 'Plugins', 'curl-plugins-body');
                ?>

                <div class="won1-info-box" style="border-color:#856404;background:#fff3cd;color:#856404;margin-top:20px;">
                    <p style="margin:0;font-size:12px;line-height:1.6;">
                        <?php esc_html_e('If you are afraid this program uses too much you might want to uninstall this plugin, but its approved. by WordPress. And does not possess powers beyond this program. Unless WordPress was hacked with a code in the plugin. Don\'t worry. These days AI can be a good tool to reduce harm by checking codes for intruders. This program was made intentionally to make hackers unable to inject programs into your system by a plugin or theme install that you do on your own terms. I can\'t be hold responsible. This program is maxed out. No more versions perhaps. This program is made for purpose of paranoidity, to treat it and feel free from prison or shackles because one thing was not right.', 'wondalizer-external-firewall'); ?>
                    </p>
                </div>
            </div>

            <div id="panel-risky" class="won2-panel">
                <div class="won1-info-box" style="border-color:#dc3545;background:#fff5f5;color:#721c24;"><h4 style="margin:0 0 5px 0;">☠️ <?php esc_html_e('Bad Potential — Obfuscated Code Detection', 'wondalizer-external-firewall'); ?></h4><p style="margin:0 0 8px 0;"><?php esc_html_e('Extensions flagged with suspicious patterns (eval, base64_decode, gzinflate, variable functions, etc.) are listed here. Blocking them will immediately prevent ALL HTTP and email access from that extension.', 'wondalizer-external-firewall'); ?></p><p style="margin:0;font-size:11px;color:#856404;background:#fff3cd;padding:6px;border-radius:3px;"><strong>⚠️ Disclaimer:</strong> <?php esc_html_e('Risk scores are capped at 78/78 because no automated detection is ever 100% accurate. A high score indicates suspicious patterns were found, but legitimate plugins may also use some of these techniques for valid reasons. Always review before blocking.', 'wondalizer-external-firewall'); ?></p></div>
                <div class="won1-bulk-bar">
                    <?php Won2_Admin_Render::bulk_btn('block_all_obs', 'danger', __('🔒 Block ALL Bad Potential', 'wondalizer-external-firewall'), 'risky'); ?>
                    <?php Won2_Admin_Render::bulk_btn('unblock_all_obs', 'success', __('🔓 Unblock ALL Bad Potential', 'wondalizer-external-firewall'), 'risky'); ?>
                </div>
                <?php
                if (empty($obs_items)): ?>
                    <p style="padding:20px; background:#fff; border:1px solid #c3c4c7; text-align:center; color:#28a745; font-weight:600;">🎉 <?php esc_html_e('No obfuscated extensions detected on your site!', 'wondalizer-external-firewall'); ?></p>
                <?php else: ?>
                <table class="won1-table wp-list-table" style="margin-top:15px;"><thead><tr><th><?php esc_html_e('Extension', 'wondalizer-external-firewall'); ?></th><th><?php esc_html_e('Score', 'wondalizer-external-firewall'); ?></th><th><?php esc_html_e('Patterns Found', 'wondalizer-external-firewall'); ?></th><th><?php esc_html_e('Status', 'wondalizer-external-firewall'); ?></th><th><?php esc_html_e('Action', 'wondalizer-external-firewall'); ?></th></tr></thead><tbody>
                <?php foreach ($obs_items as $p): ?>
                <tr data-folder="<?php echo esc_attr($p['folder']); ?>"><td><strong><?php echo esc_html($p['name']); ?></strong><br><small><?php echo esc_html($p['folder']); ?></small></td>
                <td><div class="obs-score-bar" style="width:100px;height:8px;background:#e2e3e5;border-radius:4px;overflow:hidden;margin-bottom:4px;"><div class="obs-score-fill" style="width:<?php echo (int) min(78, (int)$p['obs_score']); ?>%;height:100%;background:#dc3545;"></div></div><small><strong><?php echo (int) min(78, (int)$p['obs_score']); ?>/78</strong> Risk</small></td>
                <td><?php foreach ((array)$p['obs_patterns'] as $pat): ?><span class="won1-badge alert"><?php echo esc_html($pat); ?></span><?php endforeach; ?></td>
                <td><?php if ($p['blocked_obs']): ?><span class="won1-badge blocked"><?php esc_html_e('BLOCKED', 'wondalizer-external-firewall'); ?></span><?php else: ?><span class="won1-badge active"><?php esc_html_e('Allowed', 'wondalizer-external-firewall'); ?></span><?php endif; ?></td>
                <td><?php if ($p['blocked_obs']): ?><button type="button" class="button won1-btn success" onclick="won1ToggleObs('<?php echo esc_js($p['folder']); ?>', 'unblock_obs', this)"><?php esc_html_e('Unblock (Allow)', 'wondalizer-external-firewall'); ?></button><?php else: ?><button type="button" class="button won1-btn danger" onclick="won1ToggleObs('<?php echo esc_js($p['folder']); ?>', 'block_obs', this)"><?php esc_html_e('Block Functionality', 'wondalizer-external-firewall'); ?></button><?php endif; ?></td></tr>
                <?php endforeach; ?></tbody></table>
                <?php endif; ?>

    </div>

            
        <?php
    }
}
}