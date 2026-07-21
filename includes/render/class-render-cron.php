<?php
/**
 * Wondalizer External Firewall — Render: Cron Jobs (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Render_Cron')) {
class Won2_Render_Cron {
    public static function output($settings) {
        $cron_on = !empty($settings['cron_firewall_enabled']);
        ?>
<div id="panel-cron" class="won2-panel">
    <div class="won1-info-box" style="border-color:#ffc107;background:#fff3cd;">
        <h4 style="margin:0 0 5px 0;">⏰ <?php esc_html_e('Cron Firewall', 'wondalizer-external-firewall'); ?></h4>
        <p style="margin:0;"><?php esc_html_e('When enabled, this firewall blocks ALL external HTTP requests made during WordPress cron execution (wp-cron.php / DOING_CRON). You can explicitly whitelist specific cron hooks to allow them internet access.', 'wondalizer-external-firewall'); ?></p>
    </div>

    <?php
    $cron_stats = Won2_Admin_Render::get_cron_stats();
    $blocked_cron_hooks = (array) get_option('won2_blocked_cron_hooks', array());
    $allowed_cron_hooks = (array) get_option('won2_allowed_cron_hooks', array());
    ?>

    <div style="background:<?php echo $cron_on ? '#d4edda' : '#fff3cd'; ?>;border:1px solid <?php echo $cron_on ? '#28a745' : '#ffc107'; ?>;border-radius:4px;padding:15px;margin:15px 0;display:flex;align-items:center;justify-content:space-between;">
        <div>
            <h3 style="margin:0 0 5px 0;color:<?php echo $cron_on ? '#155724' : '#856404'; ?>;">
                <?php echo $cron_on ? '&#128308; ' . esc_html__('Cron Firewall is ON — Blocking Mode', 'wondalizer-external-firewall') : '&#128308; ' . esc_html__('Cron Firewall is OFF — Allow Mode', 'wondalizer-external-firewall'); ?>
            </h3>
            <p style="margin:0;color:<?php echo $cron_on ? '#155724' : '#856404'; ?>">
                <?php if ($cron_on) { esc_html_e('Default: DENY. All external HTTP requests during wp-cron.php are blocked unless whitelisted.', 'wondalizer-external-firewall'); } else { esc_html_e('Default: ALLOW. Cron hooks run external requests normally.', 'wondalizer-external-firewall'); } ?>
            </p>
        </div>
        <form method="post" style="display:inline;">
            <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
            <input type="hidden" name="won2_action" value="save_settings">
            <input type="hidden" name="settings[cron_firewall_enabled]" value="<?php echo $cron_on ? '0' : '1'; ?>">
            <button type="submit" class="button <?php echo $cron_on ? 'button-secondary' : 'button-primary'; ?>" style="font-size:14px;padding:8px 20px;">
                <?php echo $cron_on ? esc_html__('Turn OFF Firewall', 'wondalizer-external-firewall') : esc_html__('Turn ON Firewall', 'wondalizer-external-firewall'); ?>
            </button>
        </form>
    </div>

    <div class="won1-stats" style="display:flex;gap:15px;flex-wrap:wrap;margin-top:20px;">
        <div class="won1-statbox" style="border-left:4px solid <?php echo $cron_on ? '#28a745' : '#dc3545'; ?>;">
            <h3 style="color:<?php echo $cron_on ? '#28a745' : '#dc3545'; ?>;"><?php echo $cron_on ? esc_html__('ACTIVE', 'wondalizer-external-firewall') : esc_html__('OFF', 'wondalizer-external-firewall'); ?></h3>
            <p><?php esc_html_e('Cron Firewall Status', 'wondalizer-external-firewall'); ?></p>
        </div>
        <div class="won1-statbox">
            <h3><?php echo (int)$cron_stats['total']; ?></h3>
            <p><?php esc_html_e('Scheduled Events', 'wondalizer-external-firewall'); ?></p>
        </div>
        <div class="won1-statbox" style="border-left:4px solid #dc3545;">
            <h3 style="color:#dc3545;"><?php echo count($blocked_cron_hooks); ?></h3>
            <p><?php esc_html_e('Blocked Hooks', 'wondalizer-external-firewall'); ?></p>
        </div>
        <div class="won1-statbox" style="border-left:4px solid #28a745;">
            <h3 style="color:#28a745;"><?php echo count($allowed_cron_hooks); ?></h3>
            <p><?php esc_html_e('Allowed Hooks', 'wondalizer-external-firewall'); ?></p>
        </div>
    </div>

    <div class="won1-bulk-bar" style="margin-top:20px;">
        <?php Won2_Admin_Render::bulk_btn('block_all_cron', 'danger', __('🔒 Block ALL Cron Hooks', 'wondalizer-external-firewall')); ?>
        <?php Won2_Admin_Render::bulk_btn('unblock_all_cron', 'success', __('🔓 Unblock ALL Cron Hooks', 'wondalizer-external-firewall')); ?>
        <span style="color:#ccc;margin:0 10px;">|</span>
        <?php Won2_Admin_Render::bulk_btn('allow_all_cron', 'success', __('✅ Allow ALL Cron Hooks', 'wondalizer-external-firewall')); ?>
        <?php Won2_Admin_Render::bulk_btn('disallow_all_cron', 'danger', __('❌ Disallow ALL Cron Hooks', 'wondalizer-external-firewall')); ?>
        <span style="color:#ccc;margin:0 10px;">|</span>
        <form method="post" id="bulk-form-cron" style="display:inline;">
            <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
            <input type="hidden" name="won2_action" id="bulk-action-cron" value="block_cron_hook">
            <input type="hidden" name="selected_hooks" id="bulk-selected-cron" value="">
            <button type="submit" class="button won1-btn warning" onclick="return doBulkCronAction('block_cron_hook');"><?php esc_html_e('🔒 Block Selected', 'wondalizer-external-firewall'); ?></button>
            <button type="submit" class="button won1-btn" onclick="return doBulkCronAction('unblock_cron_hook');"><?php esc_html_e('🔓 Unblock Selected', 'wondalizer-external-firewall'); ?></button>
            <button type="submit" class="button won1-btn success" onclick="return doBulkCronAction('allow_cron_hook');"><?php esc_html_e('✅ Allow Selected', 'wondalizer-external-firewall'); ?></button>
            <button type="submit" class="button won1-btn danger" onclick="return doBulkCronAction('disallow_cron_hook');"><?php esc_html_e('❌ Disallow Selected', 'wondalizer-external-firewall'); ?></button>
        </form>
    </div>

    <table class="won1-table wp-list-table won1-cron-table" style="margin-top:15px;">
        <thead>
            <tr>
                <th style="width:30px;"><input type="checkbox" onclick="toggleAllCheckboxes(this,'cron-row-checkbox')"></th>
                <th><?php esc_html_e('Cron Hook', 'wondalizer-external-firewall'); ?></th>
                <th><?php esc_html_e('Next Run', 'wondalizer-external-firewall'); ?></th>
                <th><?php esc_html_e('Recurrence', 'wondalizer-external-firewall'); ?></th>
                <th><?php esc_html_e('HTTP Status', 'wondalizer-external-firewall'); ?></th>
                <th><?php esc_html_e('Allow List', 'wondalizer-external-firewall'); ?></th>
                <th><?php esc_html_e('Actions', 'wondalizer-external-firewall'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php
            $crons = _get_cron_array();
            $schedules = wp_get_schedules();
            $cron_rows = [];
            if (is_array($crons)) {
                foreach ($crons as $timestamp => $cronhooks) {
                    foreach ((array)$cronhooks as $hook => $args) {
                        foreach ((array)$args as $key => $event) {
                            $cron_rows[] = [
                                'hook' => $hook,
                                'timestamp' => $timestamp,
                                'schedule' => isset($event['schedule']) ? $event['schedule'] : '',
                                'interval' => isset($event['interval']) ? $event['interval'] : 0,
                            ];
                        }
                    }
                }
            }
            usort($cron_rows, function($a, $b) {
                return $a['timestamp'] <=> $b['timestamp'];
            });
            if (empty($cron_rows)):
            ?>
            <tr><td colspan="7" style="text-align:center;color:#999;padding:30px;"><?php esc_html_e('No scheduled cron events found.', 'wondalizer-external-firewall'); ?></td></tr>
            <?php else:
                foreach ($cron_rows as $row):
                    $hook = $row['hook'];
                    $is_blocked = in_array($hook, $blocked_cron_hooks, true);
                    $is_allowed = in_array($hook, $allowed_cron_hooks, true);
                    $next_run = gmdate('Y-m-d H:i:s', $row['timestamp']);
                    $recurrence = $row['schedule'] ? $row['schedule'] : __('One-time', 'wondalizer-external-firewall');
                    if (!empty($row['interval'])) {
                        $recurrence .= ' (' . human_time_diff(0, $row['interval']) . ')';
                    }
            ?>
            <tr data-hook="<?php echo esc_attr($hook); ?>">
                <td><input type="checkbox" class="cron-row-checkbox" value="<?php echo esc_attr($hook); ?>"></td>
                <td><strong><?php echo esc_html($hook); ?></strong></td>
                <td><?php echo esc_html($next_run); ?></td>
                <td><?php echo esc_html($recurrence); ?></td>
                <td>
                    <?php if ($is_blocked): ?>
                        <span class="won1-badge blocked"><?php esc_html_e('BLOCKED', 'wondalizer-external-firewall'); ?></span>
                    <?php else: ?>
                        <span class="won1-badge active"><?php esc_html_e('ALLOWED', 'wondalizer-external-firewall'); ?></span>
                    <?php endif; ?>
                </td>
                <td>
                    <?php if ($is_allowed): ?>
                        <span class="won1-badge success" style="background:#d4edda;color:#155724;border:1px solid #c3e6cb;"><?php esc_html_e('WHITELISTED', 'wondalizer-external-firewall'); ?></span>
                    <?php else: ?>
                        <span style="color:#999;">—</span>
                    <?php endif; ?>
                </td>
                <td>
                    <form method="post" style="display:inline;">
                        <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
                        <input type="hidden" name="cron_hook" value="<?php echo esc_attr($hook); ?>">
                        <?php if ($is_blocked): ?>
                            <input type="hidden" name="won2_action" value="unblock_cron_hook">
                            <button type="submit" class="button won1-btn success"><?php esc_html_e('Unblock', 'wondalizer-external-firewall'); ?></button>
                        <?php else: ?>
                            <input type="hidden" name="won2_action" value="block_cron_hook">
                            <button type="submit" class="button won1-btn danger"><?php esc_html_e('Block', 'wondalizer-external-firewall'); ?></button>
                        <?php endif; ?>
                    </form>
                    <form method="post" style="display:inline;">
                        <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
                        <input type="hidden" name="cron_hook" value="<?php echo esc_attr($hook); ?>">
                        <?php if ($is_allowed): ?>
                            <input type="hidden" name="won2_action" value="disallow_cron_hook">
                            <button type="submit" class="button won1-btn warning"><?php esc_html_e('Remove Allow', 'wondalizer-external-firewall'); ?></button>
                        <?php else: ?>
                            <input type="hidden" name="won2_action" value="allow_cron_hook">
                            <button type="submit" class="button won1-btn info" style="background:#17a2b8;color:#fff;border:none;"><?php esc_html_e('Allow', 'wondalizer-external-firewall'); ?></button>
                        <?php endif; ?>
                    </form>
                </td>
            </tr>
            <?php endforeach; endif; ?>
        </tbody>
    </table>
</div>
        <?php
    }
}
}