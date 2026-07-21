<?php
/**
 * Wondalizer External Firewall — Render: Logs (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Render_Logs')) {
class Won2_Render_Logs {
    public static function output($settings) {
        $logging_on = !empty($settings['logging_enabled']);
        ?>
<div id="panel-logs" class="won2-panel">
                <div style="margin-bottom:10px;padding:8px 12px;background:#e6f2ff;border-left:3px solid #0066cc;border-radius:3px;font-size:12px;">
                    <strong><?php esc_html_e('Legend:', 'wondalizer-external-firewall'); ?></strong>
                    <span style="color:#0066cc;font-weight:500;">■</span> <?php esc_html_e('Same-site requests (blue) — requests to your own domain are highlighted in blue for easy identification.', 'wondalizer-external-firewall'); ?>
                </div>
                <h2 style="margin-top:0;">📄 <?php esc_html_e('Recent Connection Attempts', 'wondalizer-external-firewall'); ?></h2>

                <?php
                $logger_health = array('ok' => false, 'error' => 'Logger class not loaded', 'count' => 0);
                if (class_exists('Won2_Logger')) {
                    global $wpdb;
                    $table = $wpdb->prefix . 'won2_logs';
                    $wpdb->suppress_errors(true);
                    $exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
                    if ($exists === $table) {
                        $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->prefix}won2_logs WHERE type IN ('http', 'email') AND %d = %d", 1, 1)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
                        $logger_health = array('ok' => true, 'count' => (int)$count, 'error' => '');
                    } else {
                        $logger_health = array('ok' => false, 'error' => 'Table does not exist', 'count' => 0);
                    }
                    $wpdb->suppress_errors(false);
                }
                ?>

                <div class="won1-info-box" style="margin-bottom:15px; border-color:#17a2b8;">
                    <h4 style="margin:0 0 5px 0; color:#0c5460;">🔍 <?php esc_html_e('Logger Diagnostics', 'wondalizer-external-firewall'); ?></h4>
                    <p style="margin:0 0 5px 0;">
                        <strong><?php esc_html_e('Database Table:', 'wondalizer-external-firewall'); ?></strong>
                        <?php if ($logger_health['ok']): ?>
                            <span style="color:#28a745; font-weight:bold;"><?php esc_html_e('HEALTHY', 'wondalizer-external-firewall'); ?></span>
                            (<?php echo (int)$logger_health['count']; ?> <?php esc_html_e('rows recorded', 'wondalizer-external-firewall'); ?>)
                        <?php else: ?>
                            <span style="color:#dc3545; font-weight:bold;"><?php esc_html_e('UNHEALTHY', 'wondalizer-external-firewall'); ?></span>
                            <?php if (!empty($logger_health['error'])): ?>
                                — <?php echo esc_html($logger_health['error']); ?>
                            <?php endif; ?>
                        <?php endif; ?>
                    </p>
                    <p style="margin:0; font-size:12px;color:#666;">
                        <?php esc_html_e('Check PHP error_log for WON1-TRACE and WON1-DEBUG messages if logging seems broken.', 'wondalizer-external-firewall'); ?>
                    </p>
                </div>

                <?php if (!$logging_on): ?>
                    <div class="won1-danger-box" style="background:#fff5f5;border:1px solid #fc8181;padding:15px;border-radius:4px;margin-bottom:15px;">
                        <h4 style="margin:0;color:#721c24;">⚠️ <?php esc_html_e('Logging is DISABLED in settings.', 'wondalizer-external-firewall'); ?></h4>
                    </div>
                <?php endif; ?>

                <?php
                if ($logger_health['ok']) {
                    $wpdb->suppress_errors(true);
                    $logs = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->prefix}won2_logs WHERE type IN ('http', 'email') ORDER BY created_at DESC LIMIT %d", 100)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->suppress_errors(false);
                } else {
                    $logs = [];
                }
                ?>

                <?php if (!empty($logs)): ?>
                    <form method="post" style="margin-bottom: 15px;">
                        <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
                        <input type="hidden" name="won2_action" value="clear_logs">
                        <button type="submit" class="button won1-btn danger" onclick="return confirm('<?php echo esc_js(__('Are you sure you want to completely erase all logs?', 'wondalizer-external-firewall')); ?>');">
                            🗑️ <?php esc_html_e('Clear All Logs', 'wondalizer-external-firewall'); ?>
                        </button>
                    </form>
                    <table class="won1-table won1-logs-table wp-list-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e('Time', 'wondalizer-external-firewall'); ?></th>
                                <th><?php esc_html_e('Extension', 'wondalizer-external-firewall'); ?></th>
                                <th><?php esc_html_e('Method', 'wondalizer-external-firewall'); ?></th>
                                <th><?php esc_html_e('Destination', 'wondalizer-external-firewall'); ?></th>
                                <th><?php esc_html_e('Status', 'wondalizer-external-firewall'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($logs as $log):
                                $is_blocked = !empty($log->blocked);
                                $entry_type = $log->type ?? 'http';
                                $is_email = ($entry_type === 'email');
                                $is_http  = ($entry_type === 'http');
                                $row_class = 'won1-log-row';
                                if ($is_blocked) $row_class .= ' won1-log-blocked';
                                elseif ($is_email) $row_class .= ' won1-log-email';
                                // Robust time display: convert MySQL datetime to WordPress timezone
                                $display_time = esc_html($log->created_at);
                                if (!empty($log->created_at)) {
                                    $timestamp = strtotime($log->created_at);
                                    if ($timestamp) {
                                        $formatted = wp_date(get_option('date_format') . ' ' . get_option('time_format'), $timestamp);
                                        if (!empty($formatted)) {
                                            $display_time = esc_html($formatted);
                                        }
                                    }
                                }
                            ?>
                                <tr class="<?php echo esc_attr($row_class); ?>">
                                    <td><?php echo esc_html($display_time); ?></td>
                                    <td>
                                        <strong><?php echo esc_html($log->source_name); ?></strong><br>
                                        <small><?php echo esc_html($log->source_folder); ?></small>
                                        <?php if ($log->source_type === 'core'): ?><span class="won1-badge core"><?php esc_html_e('Core', 'wondalizer-external-firewall'); ?></span><?php endif; ?>
                                        <?php if ($log->source_type === 'theme'): ?><span class="won1-badge theme"><?php esc_html_e('Theme', 'wondalizer-external-firewall'); ?></span><?php endif; ?>
                                        <?php if ($log->source_type === 'plugin'): ?><span class="won1-badge active"><?php esc_html_e('Plugin', 'wondalizer-external-firewall'); ?></span><?php endif; ?>
                                        <?php if ($log->source_type === 'mu-plugin'): ?><span class="won1-badge alert"><?php esc_html_e('MU', 'wondalizer-external-firewall'); ?></span><?php endif; ?>
                                    </td>
                                    <td>
                                        <span class="won1-badge <?php echo $is_email ? 'email' : 'alert'; ?>">
                                            <?php echo $is_email ? esc_html__('EMAIL', 'wondalizer-external-firewall') : esc_html__('HTTP', 'wondalizer-external-firewall'); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <div class="won1-url-cell" title="<?php echo esc_attr($log->url); ?>"
                                            <?php
                                            $log_url_host = wp_parse_url($log->url, PHP_URL_HOST);
                                            $site_host = wp_parse_url(home_url(), PHP_URL_HOST);
                                            if ($log_url_host && $site_host && ($log_url_host === $site_host || (substr($log_url_host, -strlen('.' . $site_host)) === '.' . $site_host) || (substr($site_host, -strlen('.' . $log_url_host)) === '.' . $log_url_host))) {
                                                echo 'style="color:#0066cc;font-weight:500;background:#e6f2ff;padding:2px 6px;border-radius:3px;"';
                                            }
                                            ?>
                                        >
                                            <?php echo esc_html($log->host ?: $log->url); ?>
                                        </div>
                                    </td>
                                    <td>
                                        <?php if ($is_blocked): ?>
                                            <span class="won1-badge blocked"><?php esc_html_e('BLOCKED', 'wondalizer-external-firewall'); ?></span>
                                            <?php if ($log->reason): ?>
                                                <br><small style="color:#dc3545;"><?php echo esc_html($log->reason); ?></small>
                                            <?php endif; ?>
                                        <?php else: ?>
                                            <span class="won1-badge active"><?php esc_html_e('ALLOWED', 'wondalizer-external-firewall'); ?></span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else: ?>
                    <div class="won1-info-box">
                        <p style="margin:0;"><?php esc_html_e('No logs found. If requests are happening but not showing, check Logging Settings.', 'wondalizer-external-firewall'); ?></p>
                    </div>
                <?php endif; ?>

            </div>


        <?php
    }
}
}