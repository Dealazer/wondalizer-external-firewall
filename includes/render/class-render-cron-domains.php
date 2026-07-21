<?php
/**
 * Wondalizer External Firewall — Render: Cron & Domains (v8.1.6)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Render_Cron_Domains')) {
class Won2_Render_Cron_Domains {
    public static function output($settings, $roster) {
        $cron_stats = Won2_Admin_Render::get_cron_stats();
        $crons = _get_cron_array();
        $blocked_cron = (array) get_option('won2_blocked_cron_hooks', []);
        $allowed_cron = (array) get_option('won2_allowed_cron_hooks', []);
        $blocked_obs = (array) get_option('won2_blocked_obfuscation', []);
        ?>
        <div id="panel-cron" class="won2-panel">
            <h2><?php esc_html_e('Cron Jobs', 'wondalizer-external-firewall'); ?></h2>
            <p><?php
                /* translators: %s: number of scheduled events */
                echo esc_html(sprintf(__('Total scheduled events: %s', 'wondalizer-external-firewall'), (int)$cron_stats['total']));
            ?></p>

            <form method="post" action="">
                <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
                <input type="hidden" name="won2_action" value="bulk_cron_block">
                <input type="hidden" name="bulk_selected_cron" id="bulk-selected-cron" value="">
                <input type="hidden" name="bulk_action_cron" id="bulk-action-cron" value="">

                <div class="won1-bulk-bar">
                    <strong><?php esc_html_e('Bulk Cron:', 'wondalizer-external-firewall'); ?></strong>
                    <button type="submit" class="button won1-btn" onclick="document.getElementById('bulk-action-cron').value='bulk_cron_block';return doBulkCronAction('bulk_cron_block');"><?php esc_html_e('Block Selected', 'wondalizer-external-firewall'); ?></button>
                    <button type="submit" class="button won1-btn" onclick="document.getElementById('bulk-action-cron').value='bulk_cron_allow';return doBulkCronAction('bulk_cron_allow');"><?php esc_html_e('Allow Selected', 'wondalizer-external-firewall'); ?></button>
                    <button type="submit" class="button won1-btn" onclick="document.getElementById('bulk-action-cron').value='block_all_cron';return true;"><?php esc_html_e('Block All', 'wondalizer-external-firewall'); ?></button>
                    <button type="submit" class="button won1-btn" onclick="document.getElementById('bulk-action-cron').value='unblock_all_cron';return true;"><?php esc_html_e('Unblock All', 'wondalizer-external-firewall'); ?></button>
                </div>

                <?php if (empty($crons)) : ?>
                    <div class="notice notice-info"><p><?php esc_html_e('No cron jobs scheduled.', 'wondalizer-external-firewall'); ?></p></div>
                <?php else : ?>
                    <table class="won1-table wp-list-table">
                        <thead><tr>
                            <th style="width:30px;"><input type="checkbox" onchange="toggleAllCheckboxes(this,'cron-row-checkbox');"></th>
                            <th><?php esc_html_e('Hook', 'wondalizer-external-firewall'); ?></th>
                            <th><?php esc_html_e('Next Run', 'wondalizer-external-firewall'); ?></th>
                            <th><?php esc_html_e('Status', 'wondalizer-external-firewall'); ?></th>
                            <th><?php esc_html_e('Actions', 'wondalizer-external-firewall'); ?></th>
                        </tr></thead>
                        <tbody>
                        <?php
                        $seen = [];
                        foreach ($crons as $timestamp => $hooks) {
                            foreach ((array)$hooks as $hook => $args) {
                                if (isset($seen[$hook])) continue;
                                $seen[$hook] = true;
                                $is_blocked = in_array($hook, $blocked_cron, true);
                                $is_allowed = in_array($hook, $allowed_cron, true);
                                ?>
                                <tr>
                                    <td><input type="checkbox" class="cron-row-checkbox" value="<?php echo esc_attr($hook); ?>"></td>
                                    <td><code><?php echo esc_html($hook); ?></code></td>
                                    <td><?php echo esc_html(human_time_diff($timestamp, time()) . ' ' . __('from now', 'wondalizer-external-firewall')); ?></td>
                                    <td>
                                        <?php if ($is_blocked) : ?>
                                            <span class="won1-badge blocked"><?php esc_html_e('Blocked', 'wondalizer-external-firewall'); ?></span>
                                        <?php elseif ($is_allowed) : ?>
                                            <span class="won1-badge active"><?php esc_html_e('Allowed', 'wondalizer-external-firewall'); ?></span>
                                        <?php else : ?>
                                            <span class="won1-badge core"><?php esc_html_e('Default', 'wondalizer-external-firewall'); ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($is_blocked) : ?>
                                            <button type="submit" class="button won1-btn" name="cron_hook" value="<?php echo esc_attr($hook); ?>" onclick="this.form.querySelector('[name=\'won2_action\']').value='unblock_cron_hook';"><?php esc_html_e('Unblock', 'wondalizer-external-firewall'); ?></button>
                                        <?php else : ?>
                                            <button type="submit" class="button won1-btn" name="cron_hook" value="<?php echo esc_attr($hook); ?>" onclick="this.form.querySelector('[name=\'won2_action\']').value='block_cron_hook';"><?php esc_html_e('Block', 'wondalizer-external-firewall'); ?></button>
                                        <?php endif; ?>
                                        <?php if ($is_allowed) : ?>
                                            <button type="submit" class="button won1-btn" name="cron_hook" value="<?php echo esc_attr($hook); ?>" onclick="this.form.querySelector('[name=\'won2_action\']').value='disallow_cron_hook';"><?php esc_html_e('Disallow', 'wondalizer-external-firewall'); ?></button>
                                        <?php else : ?>
                                            <button type="submit" class="button won1-btn" name="cron_hook" value="<?php echo esc_attr($hook); ?>" onclick="this.form.querySelector('[name=\'won2_action\']').value='allow_cron_hook';"><?php esc_html_e('Allow', 'wondalizer-external-firewall'); ?></button>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php
                            }
                        }
                        ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </form>

            <h2 style="margin-top:30px;"><?php esc_html_e('Obfuscation', 'wondalizer-external-firewall'); ?></h2>
            <?php
            $obs_items = array_filter($roster, function($p){
                if (!empty($p['has_obfuscated'])) {
                    $folder = strtolower($p['folder'] ?? '');
                    if (strpos($folder, 'wondalizer-external-firewall') !== false || strpos($folder, 'wondalizer-fw') !== false) {
                        return false;
                    }
                    return true;
                }
                return false;
            });
            if (empty($obs_items)) : ?>
                <div class="notice notice-info"><p><?php esc_html_e('No obfuscated extensions detected.', 'wondalizer-external-firewall'); ?></p></div>
            <?php else : ?>
                <form method="post" action="">
                    <?php wp_nonce_field('won2_action', 'won2_nonce'); ?>
                    <table class="won1-table wp-list-table">
                        <thead><tr>
                            <th><?php esc_html_e('Extension', 'wondalizer-external-firewall'); ?></th>
                            <th><?php esc_html_e('Status', 'wondalizer-external-firewall'); ?></th>
                            <th><?php esc_html_e('Actions', 'wondalizer-external-firewall'); ?></th>
                        </tr></thead>
                        <tbody>
                        <?php foreach ($obs_items as $p) :
                            $is_blocked = in_array($p['folder'], $blocked_obs, true);
                            ?>
                            <tr>
                                <td><strong><?php echo esc_html($p['name']); ?></strong><br><code><?php echo esc_html($p['folder']); ?></code></td>
                                <td><?php echo $is_blocked ? '<span class="won1-badge blocked">' . esc_html__('Blocked', 'wondalizer-external-firewall') . '</span>' : '<span class="won1-badge active">' . esc_html__('Allowed', 'wondalizer-external-firewall') . '</span>'; ?></td>
                                <td>
                                    <input type="hidden" name="won2_action" value="<?php echo $is_blocked ? 'unblock_obs' : 'block_obs'; ?>">
                                    <button type="submit" class="button won1-btn" name="single_folder" value="<?php echo esc_attr($p['folder']); ?>"><?php echo $is_blocked ? esc_html__('Allow', 'wondalizer-external-firewall') : esc_html__('Block', 'wondalizer-external-firewall'); ?></button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <div class="won1-bulk-bar" style="margin-top:10px;">
                        <button type="submit" class="button won1-btn" name="won2_action" value="block_all_obs"><?php esc_html_e('Block All Obs', 'wondalizer-external-firewall'); ?></button>
                        <button type="submit" class="button won1-btn" name="won2_action" value="unblock_all_obs"><?php esc_html_e('Unblock All Obs', 'wondalizer-external-firewall'); ?></button>
                    </div>
                </form>
            <?php endif; ?>
        </div>
        <?php
    }
}
}