<?php
/**
 * Wondalizer External Firewall — Admin Tables (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Admin_Tables')) {
class Won2_Admin_Tables {

    public static function render_roster_table($items, $type, $section_id, $log_counts, $tab = 'roster') {
        if (!is_array($log_counts)) {
            $log_counts = [];
        }

        $title = '';
        if ($type === 'core') $title = __('WordPress Core Protocols', 'wondalizer-external-firewall');
        elseif ($type === 'theme') $title = __('Active & Installed Themes', 'wondalizer-external-firewall');
        else $title = __('Installed Plugins', 'wondalizer-external-firewall');

        echo '<div class="won1-section ' . esc_attr($type) . '-section" id="' . esc_attr($section_id) . '">';
        echo '<h3>' . esc_html($title) . ' <span style="font-weight:normal;font-size:12px;color:#666;">(' . count($items) . ')</span></h3>';
        echo '<table class="won1-table wp-list-table">';
        echo '<thead><tr>';
        echo '<th style="width: 30px;"><input type="checkbox" onclick="toggleAllCheckboxes(this, \'cb-' . esc_attr($type) . '\')"></th>';
        echo '<th>' . esc_html__('Extension / Source', 'wondalizer-external-firewall') . '</th>';
        echo '<th>' . esc_html__('Status', 'wondalizer-external-firewall') . '</th>';
        echo '<th>' . esc_html__('External Connections (30d)', 'wondalizer-external-firewall') . '</th>';
        echo '<th>' . esc_html__('Actions', 'wondalizer-external-firewall') . '</th>';
        echo '</tr></thead>';
        echo '<tbody>';

        if (empty($items)) {
            echo '<tr><td colspan="5" style="text-align:center;color:#999;padding:15px;">' . esc_html__('No items in this category.', 'wondalizer-external-firewall') . '</td></tr>';
        } else {
            foreach ($items as $p) {
                $folder = $p['folder'];
                $cb_class = 'cb-' . $type . ' cb-' . $type . '-' . $type;
                $is_blocked = !empty($p['blocked_http']);
                $is_protected = !empty($p['is_protected']);
                $status_badge = $is_protected
                    ? '<span class="won1-badge protected">' . esc_html__('PROTECTED', 'wondalizer-external-firewall') . '</span>'
                    : ($is_blocked 
                        ? '<span class="won1-badge blocked">' . esc_html__('BLOCKED', 'wondalizer-external-firewall') . '</span>'
                        : '<span class="won1-badge active">' . esc_html__('ALLOWED', 'wondalizer-external-firewall') . '</span>');

                $allowed_cnt = $log_counts[$folder]['allowed'] ?? 0;
                $blocked_cnt = $log_counts[$folder]['blocked'] ?? 0;

                // Safety net: re-filter old cached domains that may contain comment URLs
                $display_domains = $p['scanned_domains'] ?? [];
                if (!empty($display_domains) && class_exists('Won2_Scan')) {
                    if (!isset($p['scan_version']) || $p['scan_version'] !== Won2_Scan::SCAN_VERSION) {
                        try {
                            $display_domains = Won2_Scan::filter_display_domains($folder, $display_domains);
                        } catch (\Throwable $e) {
                            $display_domains = [];
                        }
                    }
                }

                echo '<tr class="' . ($is_blocked ? 'blocked-row' : '') . '">';
                echo '<td>';
                if (!$is_protected) {
                    echo '<input type="checkbox" class="' . esc_attr($cb_class) . '" value="' . esc_attr($folder) . '">';
                } else {
                    echo '<span title="' . esc_attr__('Protected', 'wondalizer-external-firewall') . '">🔒</span>';
                }
                echo '</td>';
                echo '<td><strong>' . esc_html($p['name']) . '</strong><br><small>' . esc_html($folder) . '</small>';
                if (!empty($display_domains)) {
                    echo '<div class="won1-domains" style="margin-top:5px;">';
                    foreach (array_slice($display_domains, 0, 5) as $dom) {
                        echo '<span>' . esc_html($dom) . '</span>';
                    }
                    if (count($display_domains) > 5) {
                        echo '<span>+ ' . (count($display_domains) - 5) . ' more</span>';
                    }
                    echo '</div>';
                } elseif (!empty($p['scanned_domains'])) {
                    echo '<div class="won1-domains" style="margin-top:5px;">';
                    echo '<span style="color:#999;font-style:italic;">' . esc_html__('Rescan needed to discover domains', 'wondalizer-external-firewall') . '</span>';
                    echo '</div>';
                }
                echo '</td>';
                echo '<td>' . wp_kses_post($status_badge) . '</td>';
                echo '<td>';
                echo '<span style="color:#28a745;">✔ Allowed: ' . (int)$allowed_cnt . '</span><br>';
                echo '<span style="color:#dc3545;">✖ Blocked: ' . (int)$blocked_cnt . '</span>';
                echo '</td>';
                echo '<td>';
                if (!$is_protected) {
                    echo '<button type="button" class="button won1-btn info" onclick="openDomainModal(\'' . esc_js($folder) . '\')">🌐 ' . esc_html__('Domains', 'wondalizer-external-firewall') . '</button>';
                    echo '<form method="post" style="display:inline;">';
                    wp_nonce_field('won2_action', 'won2_nonce', true, true);
                    echo '<input type="hidden" name="won1_tab" value="' . esc_attr($tab) . '">';
                    echo '<input type="hidden" name="single_folder" value="' . esc_attr($folder) . '">';
                    if ($is_blocked) {
                        echo '<input type="hidden" name="won2_action" value="unblock">';
                        echo '<button type="submit" class="button won1-btn success">' . esc_html__('Unblock', 'wondalizer-external-firewall') . '</button>';
                    } else {
                        echo '<input type="hidden" name="won2_action" value="block">';
                        echo '<button type="submit" class="button won1-btn danger">' . esc_html__('Block', 'wondalizer-external-firewall') . '</button>';
                    }
                    echo '</form>';
                } else {
                    echo '<em>' . esc_html__('Protected system extension', 'wondalizer-external-firewall') . '</em>';
                }
                echo '</td>';
                echo '</tr>';
            }
        }
        echo '</tbody></table></div>';
    }

    public static function render_email_table($items, $section_id, $log_counts, $tab = 'emails') {
        if (!is_array($log_counts)) {
            $log_counts = [];
        }

        $type = 'email';
        echo '<div class="won1-section email-section" id="' . esc_attr($section_id) . '">';
        echo '<h3>' . esc_html__('Email Controls', 'wondalizer-external-firewall') . ' <span style="font-weight:normal;font-size:12px;color:#666;">(' . count($items) . ')</span></h3>';
        echo '<table class="won1-table wp-list-table">';
        echo '<thead><tr>';
        echo '<th style="width: 30px;"><input type="checkbox" onclick="toggleAllCheckboxes(this, \'cb-' . esc_attr($type) . '\')"></th>';
        echo '<th>' . esc_html__('Extension / Source', 'wondalizer-external-firewall') . '</th>';
        echo '<th>' . esc_html__('Status', 'wondalizer-external-firewall') . '</th>';
        echo '<th>' . esc_html__('Emails Sent / Blocked (30d)', 'wondalizer-external-firewall') . '</th>';
        echo '<th>' . esc_html__('Actions', 'wondalizer-external-firewall') . '</th>';
        echo '</tr></thead>';
        echo '<tbody>';

        if (empty($items)) {
            echo '<tr><td colspan="5" style="text-align:center;color:#999;padding:15px;">' . esc_html__('No items in this category.', 'wondalizer-external-firewall') . '</td></tr>';
        } else {
            foreach ($items as $p) {
                $folder = $p['folder'];
                $cb_class = 'cb-' . $type . ' cb-' . $type . '-regular';
                $is_blocked = !empty($p['blocked_email']);
                $is_protected = !empty($p['is_protected']);
                $status_badge = $is_protected
                    ? '<span class="won1-badge protected">' . esc_html__('PROTECTED', 'wondalizer-external-firewall') . '</span>'
                    : ($is_blocked 
                        ? '<span class="won1-badge blocked">' . esc_html__('BLOCKED', 'wondalizer-external-firewall') . '</span>'
                        : '<span class="won1-badge active">' . esc_html__('ALLOWED', 'wondalizer-external-firewall') . '</span>');

                $allowed_cnt = $log_counts[$folder]['allowed'] ?? 0;
                $blocked_cnt = $log_counts[$folder]['blocked'] ?? 0;

                echo '<tr class="' . ($is_blocked ? 'blocked-row' : '') . '">';
                echo '<td>';
                if (!$is_protected) {
                    echo '<input type="checkbox" class="' . esc_attr($cb_class) . '" value="' . esc_attr($folder) . '">';
                } else {
                    echo '<span title="' . esc_attr__('Protected', 'wondalizer-external-firewall') . '">🔒</span>';
                }
                echo '</td>';
                echo '<td><strong>' . esc_html($p['name']) . '</strong><br><small>' . esc_html($folder) . '</small></td>';
                echo '<td>' . wp_kses_post($status_badge) . '</td>';
                echo '<td>';
                echo '<span style="color:#28a745;">✔ Sent: ' . (int)$allowed_cnt . '</span><br>';
                echo '<span style="color:#dc3545;">✖ Blocked: ' . (int)$blocked_cnt . '</span>';
                echo '</td>';
                echo '<td>';
                if (!$is_protected) {
                    echo '<form method="post" style="display:inline;">';
                    wp_nonce_field('won2_action', 'won2_nonce', true, true);
                    echo '<input type="hidden" name="won1_tab" value="' . esc_attr($tab) . '">';
                    echo '<input type="hidden" name="single_folder" value="' . esc_attr($folder) . '">';
                    if ($is_blocked) {
                        echo '<input type="hidden" name="won2_action" value="unblock_email">';
                        echo '<button type="submit" class="button won1-btn success">' . esc_html__('Allow Emails', 'wondalizer-external-firewall') . '</button>';
                    } else {
                        echo '<input type="hidden" name="won2_action" value="block_email">';
                        echo '<button type="submit" class="button won1-btn danger">' . esc_html__('Block Emails', 'wondalizer-external-firewall') . '</button>';
                    }
                    echo '</form>';
                } else {
                    echo '<em>' . esc_html__('Protected system extension', 'wondalizer-external-firewall') . '</em>';
                }
                echo '</td>';
                echo '</tr>';
            }
        }
        echo '</tbody></table></div>';
    }

    public static function render_log_table($type = 'http', $limit = 50) {
        $logs = Won2_Logger::init()->get_recent($limit, $type);
        if (empty($logs)) {
            echo '<p class="won1-info-box">' . esc_html__('No logs found.', 'wondalizer-external-firewall') . '</p>';
            return;
        }
        echo '<table class="won1-table">';
        echo '<thead><tr><th>' . esc_html__('Time', 'wondalizer-external-firewall') . '</th><th>' . esc_html__('URL/To', 'wondalizer-external-firewall') . '</th><th>' . esc_html__('Host', 'wondalizer-external-firewall') . '</th><th>' . esc_html__('Status', 'wondalizer-external-firewall') . '</th><th>' . esc_html__('Reason', 'wondalizer-external-firewall') . '</th></tr></thead>';
        echo '<tbody>';
        foreach ($logs as $log) {
            $is_same = !empty($log['same_site']);
            $row_style = $is_same ? ' style="background:#e6f2ff;"' : '';
            $status_class = $log['status'] === 'BLOCKED' ? 'won1-badge blocked' : 'won1-badge active';
            echo '<tr' . wp_kses_post($row_style) . '>';
            echo '<td>' . esc_html($log['created_at']) . '</td>';
            echo '<td class="won1-url-cell">' . esc_html($log['url'] ?? $log['to']) . '</td>';
            echo '<td>' . esc_html($log['host']) . '</td>';
            echo '<td><span class="' . esc_attr($status_class) . '">' . esc_html($log['status']) . '</span></td>';
            echo '<td>' . esc_html($log['reason']) . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }
}
}
