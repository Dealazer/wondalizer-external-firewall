<?php
/**
 * Wondalizer External Firewall — Admin Render Initializer (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Admin_Render')) {

class Won2_Admin_Render {

    public static function get_cron_stats() {
        $crons = _get_cron_array();
        $total = 0;
        if (is_array($crons)) {
            foreach ($crons as $timestamp => $cronhooks) {
                foreach ((array)$cronhooks as $hook => $args) {
                    foreach ((array)$args as $event) {
                        $total++;
                    }
                }
            }
        }
        return ['total' => $total];
    }

    public static function won1_render_curl_section($items, $section_title, $section_id) {
        if (empty($items)) {
            echo '<h3 style="margin:20px 0 10px 0;padding:8px 12px;background:#f0f0f0;border-left:4px solid #007cba;border-radius:3px;font-size:14px;">' . esc_html($section_title) . ' <span style="font-weight:normal;color:#666;">(0)</span></h3>';
            echo '<p style="color:#999;padding:10px 12px;border:1px dashed #ccc;background:#fafafa;">' . esc_html__('No extensions found in this category. Try clicking Rescan All Extensions above.', 'wondalizer-external-firewall') . '</p>';
            return;
        }
        usort($items, function($a, $b) {
            $ap = !empty($a['rewritten']);
            $bp = !empty($b['rewritten']);
            if ($ap !== $bp) return $ap ? -1 : 1;
            return strcasecmp($a['name'], $b['name']);
        });
        echo '<h3 style="margin:20px 0 10px 0;padding:8px 12px;background:#f0f0f0;border-left:4px solid #007cba;border-radius:3px;font-size:14px;">' . esc_html($section_title) . ' <span style="font-weight:normal;color:#666;">(' . count($items) . ')</span></h3>';
        echo '<table class="won1-table wp-list-table" style="margin-top:5px;"><thead><tr>';
        echo '<th style="width:30px;"><input type="checkbox" class="select-all-curl-section" data-section="' . esc_attr($section_id) . '" onchange="toggleSection(\'' . esc_js($section_id) . '\', this.checked);">';
        echo '<th>' . esc_html__('Extension', 'wondalizer-external-firewall') . '</th>';
        echo '<th>' . esc_html__('cURL', 'wondalizer-external-firewall') . '</th>';
        echo '<th>' . esc_html__('Sockets', 'wondalizer-external-firewall') . '</th>';
        echo '<th>' . esc_html__('PHP Mail()', 'wondalizer-external-firewall') . '</th>';
        echo '<th>' . esc_html__('Capabilities', 'wondalizer-external-firewall') . '</th>';
        echo '</tr></thead><tbody id="' . esc_attr($section_id) . '">';
        foreach ($items as $p) {
            if (!empty($p['is_curl_protected'])) {
                echo '<tr class="cache-row" data-folder="' . esc_attr($p['folder']) . '" style="background:#fff3cd;">';
                echo '<td><span title="' . esc_attr__('Protected', 'wondalizer-external-firewall') . '">&#128274;</span></td>';
                echo '<td><strong>' . esc_html($p['name']) . '</strong><br><small>' . esc_html($p['folder']) . '</small></td>';
                echo '<td colspan="3" style="text-align:center;"><span class="won1-badge protected" style="background:#856404;color:#fff;">' . esc_html__('PROTECTED', 'wondalizer-external-firewall') . '</span> <em style="color:#856404;font-size:12px;">' . esc_html__('Rewriting this plugin is totally unnecessary and will break the firewall.', 'wondalizer-external-firewall') . '</em></td>';
                echo '<td><span class="won1-badge protected" style="background:#856404;color:#fff;">' . esc_html__('System Protection', 'wondalizer-external-firewall') . '</span></td>';
                echo '</tr>';
                continue;
            }

            $rw = (array) get_option('won2_rewritten_plugins', []);
            $r = isset($rw[$p['folder']]) ? $rw[$p['folder']] : [];
            if ($r === true) $r = ['curl'=>true,'sock'=>true,'mail'=>true];
            if (!is_array($r)) $r = [];
            $any = !empty($r);
            // Ensure all new has_* keys exist with default false (for cached data from older scans)
            $new_has_keys = ['has_stream_select','has_stream_socket_enable_crypto','has_stream_socket_get_name','has_stream_socket_pair','has_stream_socket_shutdown','has_stream_context_default','has_stream_set_chunk_size','has_proc_open_network','has_popen_network','has_socket_addrinfo','has_socket_cmsg_space','has_socket_wsa','has_socket_set_nonblocking','has_getprotobyname','has_inet_pton','has_net_get_interfaces','has_openssl_socket','has_gethostbynamel','has_gethostname','has_mailparse','has_ezmlm_hash','has_email_class','has_notification_send','has_message_send','has_imap_open','has_pop3_class','has_nntp_class','has_smtp_port_config','has_mail_server_config','has_send_email_generic','has_mail_to_url','has_wp_mail_smtp','has_email_queue','has_soap','has_ftp','has_xmlrpc','has_rest_api'];
            foreach ($new_has_keys as $key) {
                if (!isset($p[$key])) $p[$key] = false;
            }
            $show_row = $p['has_curl'] || $p['has_curl_multi'] || $p['has_curl_share']
                || $p['has_curl_indirect'] || $p['has_curl_class'] || $p['has_curl_namespace']
                || $p['has_curl_file'] || $p['has_curl_easy'] || $p['has_curl_mime']
                || $p['has_curl_form'] || $p['has_curl_any'] || $p['has_curlopt']
                || $p['has_fsockopen'] || $p['has_socket_raw'] || $p['has_stream_socket']
                || $p['has_socket_extended'] || $p['has_stream_extended'] || $p['has_dns_lookup']
                || $p['has_socket_any'] || $p['has_stream_any'] || $p['has_php_mail']
                || $p['has_wp_mail'] || $p['has_phpmailer'] || $p['has_smtp_class']
                || $p['has_swiftmailer'] || $p['has_mail_extended'] || $p['has_mail_any']
                || $p['has_sendmail'] || $p['has_wp_http'] || $p['has_wp_http_api']
                || $p['has_guzzle'] || $p['has_requests_lib'] || $p['has_http_client']
                || $p['has_wp_http_any'] || $p['has_file_get_contents'] || $p['has_fopen_any']
                || $p['has_copy_any'] || $p['has_readfile_any'] || $p['has_file_any']
                || $p['has_wp_http_obj'] || $p['has_requests_obj'] || $p['has_symfony_http']
                || $p['has_laravel_http'] || $p['has_react_http'] || $p['has_amp_http']
                || $p['has_stream_select'] || $p['has_stream_socket_enable_crypto'] || $p['has_stream_socket_get_name']
                || $p['has_stream_socket_pair'] || $p['has_stream_socket_shutdown'] || $p['has_stream_context_default']
                || $p['has_stream_set_chunk_size'] || $p['has_proc_open_network'] || $p['has_popen_network']
                || $p['has_socket_addrinfo'] || $p['has_socket_cmsg_space'] || $p['has_socket_wsa']
                || $p['has_socket_set_nonblocking'] || $p['has_getprotobyname'] || $p['has_inet_pton']
                || $p['has_net_get_interfaces'] || $p['has_openssl_socket'] || $p['has_gethostbynamel']
                || $p['has_gethostname'] || $p['has_mailparse'] || $p['has_ezmlm_hash']
                || $p['has_email_class'] || $p['has_notification_send'] || $p['has_message_send']
                || $p['has_imap_open'] || $p['has_pop3_class'] || $p['has_nntp_class']
                || $p['has_smtp_port_config'] || $p['has_mail_server_config'] || $p['has_send_email_generic']
                || $p['has_mail_to_url'] || $p['has_wp_mail_smtp'] || $p['has_email_queue']
                || $p['has_soap'] || $p['has_ftp'] || $p['has_xmlrpc'] || $p['has_rest_api'] || $any;
            // Always show extensions in the roster so cURL cache section is never empty
            if (!$show_row && !empty($p['folder']) && empty($p['is_curl_protected'])) {
                $show_row = true;
            }
            if (!$show_row) continue;
            echo '<tr class="cache-row' . ($any ? ' patched-row' : '') . '" data-folder="' . esc_attr($p['folder']) . '">';
            echo '<td><input type="checkbox" class="plugin-cb curl-cb" value="' . esc_attr($p['folder']) . '"></td>';
            echo '<td><strong>' . esc_html($p['name']) . '</strong><br><small>' . esc_html($p['folder']) . '</small></td>';

            // cURL column
            echo '<td>';
            if ($p['has_curl'] || $p['has_curl_multi'] || $p['has_curl_share']
                || $p['has_curl_indirect'] || $p['has_curl_class'] || $p['has_curl_namespace']
                || $p['has_curl_file'] || $p['has_curl_easy'] || $p['has_curl_mime']
                || $p['has_curl_form'] || $p['has_curl_any'] || $p['has_curlopt']
                || $p['has_wp_http'] || $p['has_wp_http_api'] || $p['has_guzzle']
                || $p['has_requests_lib'] || $p['has_http_client'] || $p['has_wp_http_any']
                || $p['has_wp_http_obj'] || $p['has_requests_obj'] || $p['has_symfony_http']
                || $p['has_laravel_http'] || $p['has_react_http'] || $p['has_amp_http']
                || !empty($r['curl'])) {
                echo '<div class="method-group">';
                if (!empty($r['curl'])) {
                    echo '<span class="won1-badge rewritten">' . esc_html__('Patched', 'wondalizer-external-firewall') . '</span>';
                    echo '<button type="button" class="button" data-folder="' . esc_attr($p['folder']) . '" data-method="curl" onclick="restoreMethod(\'' . esc_js($p['folder']) . '\', \'curl\', this);">' . esc_html__('Restore', 'wondalizer-external-firewall') . '</button>';
                } else {
                    echo '<span class="won1-badge inactive">' . esc_html__('Original', 'wondalizer-external-firewall') . '</span>';
                    echo '<button type="button" class="button button-primary" data-folder="' . esc_attr($p['folder']) . '" data-method="curl" onclick="rewriteMethod(\'' . esc_js($p['folder']) . '\', \'curl\', this);">' . esc_html__('Rewrite', 'wondalizer-external-firewall') . '</button>';
                }
                echo '</div>';
            } else {
                echo '<span style="color:#ccc;">—</span>';
            }
            echo '</td>';

            // Sockets column
            echo '<td>';
            if ($p['has_fsockopen'] || $p['has_socket_raw'] || $p['has_stream_socket']
                || $p['has_socket_extended'] || $p['has_stream_extended'] || $p['has_dns_lookup']
                || $p['has_socket_any'] || $p['has_stream_any'] || !empty($r['sock'])) {
                echo '<div class="method-group">';
                if (!empty($r['sock'])) {
                    echo '<span class="won1-badge rewritten">' . esc_html__('Patched', 'wondalizer-external-firewall') . '</span>';
                    echo '<button type="button" class="button" data-folder="' . esc_attr($p['folder']) . '" data-method="sock" onclick="restoreMethod(\'' . esc_js($p['folder']) . '\', \'sock\', this);">' . esc_html__('Restore', 'wondalizer-external-firewall') . '</button>';
                } else {
                    echo '<span class="won1-badge inactive">' . esc_html__('Original', 'wondalizer-external-firewall') . '</span>';
                    echo '<button type="button" class="button button-primary" data-folder="' . esc_attr($p['folder']) . '" data-method="sock" onclick="rewriteMethod(\'' . esc_js($p['folder']) . '\', \'sock\', this);">' . esc_html__('Rewrite', 'wondalizer-external-firewall') . '</button>';
                }
                echo '</div>';
            } else {
                echo '<span style="color:#ccc;">—</span>';
            }
            echo '</td>';

            // Mail column
            echo '<td>';
            if ($p['has_php_mail'] || $p['has_wp_mail'] || $p['has_phpmailer']
                || $p['has_smtp_class'] || $p['has_swiftmailer'] || $p['has_mail_extended']
                || $p['has_mail_any'] || $p['has_sendmail'] || !empty($r['mail'])) {
                echo '<div class="method-group">';
                if (!empty($r['mail'])) {
                    echo '<span class="won1-badge rewritten">' . esc_html__('Patched', 'wondalizer-external-firewall') . '</span>';
                    echo '<button type="button" class="button" data-folder="' . esc_attr($p['folder']) . '" data-method="mail" onclick="restoreMethod(\'' . esc_js($p['folder']) . '\', \'mail\', this);">' . esc_html__('Restore', 'wondalizer-external-firewall') . '</button>';
                } else {
                    echo '<span class="won1-badge inactive">' . esc_html__('Original', 'wondalizer-external-firewall') . '</span>';
                    echo '<button type="button" class="button button-primary" data-folder="' . esc_attr($p['folder']) . '" data-method="mail" onclick="rewriteMethod(\'' . esc_js($p['folder']) . '\', \'mail\', this);">' . esc_html__('Rewrite', 'wondalizer-external-firewall') . '</button>';
                }
                echo '</div>';
            } else {
                echo '<span style="color:#ccc;">—</span>';
            }
            echo '</td>';

            // Capabilities column
            echo '<td>';
            if ($p['has_curl']) echo '<span class="won1-badge alert">cURL</span>';
            if (!empty($p['has_curl_multi'])) echo '<span class="won1-badge alert" style="background:#ffe0b2;color:#e65100;">cURL Multi</span>';
            if (!empty($p['has_curl_share'])) echo '<span class="won1-badge alert" style="background:#ffe0b2;color:#e65100;">cURL Share</span>';
            if (!empty($p['has_curl_indirect'])) echo '<span class="won1-badge alert" style="background:#ffe0b2;color:#e65100;">cURL Indirect</span>';
            if (!empty($p['has_curl_class'])) echo '<span class="won1-badge alert" style="background:#ffe0b2;color:#e65100;">cURL Class</span>';
            if (!empty($p['has_curl_namespace'])) echo '<span class="won1-badge alert" style="background:#ffe0b2;color:#e65100;">cURL NS</span>';
            if (!empty($p['has_curl_file'])) echo '<span class="won1-badge alert" style="background:#ffe0b2;color:#e65100;">cURL File</span>';
            if (!empty($p['has_curl_easy'])) echo '<span class="won1-badge alert" style="background:#ffe0b2;color:#e65100;">cURL Easy</span>';
            if (!empty($p['has_curl_mime'])) echo '<span class="won1-badge alert" style="background:#ffe0b2;color:#e65100;">cURL MIME</span>';
            if (!empty($p['has_curl_form'])) echo '<span class="won1-badge alert" style="background:#ffe0b2;color:#e65100;">cURL Form</span>';
            if (!empty($p['has_curl_any'])) echo '<span class="won1-badge alert" style="background:#ffe0b2;color:#e65100;">cURL Any</span>';
            if (!empty($p['has_curlopt'])) echo '<span class="won1-badge alert" style="background:#ffe0b2;color:#e65100;">CURLOPT</span>';
            if ($p['has_fsockopen']) echo '<span class="won1-badge alert">Sockets</span>';
            if (!empty($p['has_socket_raw'])) echo '<span class="won1-badge alert" style="background:#c8e6c9;color:#1b5e20;">Raw Sock</span>';
            if (!empty($p['has_stream_socket'])) echo '<span class="won1-badge alert" style="background:#c8e6c9;color:#1b5e20;">Stream</span>';
            if (!empty($p['has_socket_extended'])) echo '<span class="won1-badge alert" style="background:#c8e6c9;color:#1b5e20;">Sock Ext</span>';
            if (!empty($p['has_stream_extended'])) echo '<span class="won1-badge alert" style="background:#c8e6c9;color:#1b5e20;">Stream Ext</span>';
            if (!empty($p['has_dns_lookup'])) echo '<span class="won1-badge alert" style="background:#c8e6c9;color:#1b5e20;">DNS</span>';
            if (!empty($p['has_socket_any'])) echo '<span class="won1-badge alert" style="background:#c8e6c9;color:#1b5e20;">Socket Any</span>';
            if (!empty($p['has_stream_any'])) echo '<span class="won1-badge alert" style="background:#c8e6c9;color:#1b5e20;">Stream Any</span>';
            if (!empty($p['has_wp_http'])) echo '<span class="won1-badge alert" style="background:#d1ecf1;color:#0c5460;">WP HTTP</span>';
            if (!empty($p['has_wp_http_api'])) echo '<span class="won1-badge alert" style="background:#d1ecf1;color:#0c5460;">WP HTTP API</span>';
            if (!empty($p['has_guzzle'])) echo '<span class="won1-badge alert" style="background:#d1ecf1;color:#0c5460;">Guzzle</span>';
            if (!empty($p['has_requests_lib'])) echo '<span class="won1-badge alert" style="background:#d1ecf1;color:#0c5460;">Requests</span>';
            if (!empty($p['has_http_client'])) echo '<span class="won1-badge alert" style="background:#d1ecf1;color:#0c5460;">HTTP Client</span>';
            if (!empty($p['has_wp_http_any'])) echo '<span class="won1-badge alert" style="background:#d1ecf1;color:#0c5460;">WP Remote</span>';
            if (!empty($p['has_wp_http_obj'])) echo '<span class="won1-badge alert" style="background:#d1ecf1;color:#0c5460;">WP HTTP Obj</span>';
            if (!empty($p['has_requests_obj'])) echo '<span class="won1-badge alert" style="background:#d1ecf1;color:#0c5460;">Requests Obj</span>';
            if (!empty($p['has_symfony_http'])) echo '<span class="won1-badge alert" style="background:#d1ecf1;color:#0c5460;">Symfony</span>';
            if (!empty($p['has_laravel_http'])) echo '<span class="won1-badge alert" style="background:#d1ecf1;color:#0c5460;">Laravel</span>';
            if (!empty($p['has_react_http'])) echo '<span class="won1-badge alert" style="background:#d1ecf1;color:#0c5460;">React</span>';
            if (!empty($p['has_amp_http'])) echo '<span class="won1-badge alert" style="background:#d1ecf1;color:#0c5460;">Amp</span>';
            if (!empty($p['has_file_get_contents'])) echo '<span class="won1-badge alert" style="background:#fff3cd;color:#856404;">file_get_contents</span>';
            if (!empty($p['has_fopen_any'])) echo '<span class="won1-badge alert" style="background:#fff3cd;color:#856404;">fopen</span>';
            if (!empty($p['has_copy_any'])) echo '<span class="won1-badge alert" style="background:#fff3cd;color:#856404;">copy</span>';
            if (!empty($p['has_readfile_any'])) echo '<span class="won1-badge alert" style="background:#fff3cd;color:#856404;">readfile</span>';
            if (!empty($p['has_file_any'])) echo '<span class="won1-badge alert" style="background:#fff3cd;color:#856404;">File I/O</span>';
            if ($p['has_php_mail']) echo '<span class="won1-badge alert" style="background:#e8d5ff;color:#5b21b6;">PHP Mail()</span>';
            if (!empty($p['has_wp_mail'])) echo '<span class="won1-badge alert" style="background:#e8d5ff;color:#5b21b6;">wp_mail()</span>';
            if (!empty($p['has_phpmailer'])) echo '<span class="won1-badge alert" style="background:#f8bbd0;color:#880e4f;">PHPMailer</span>';
            if (!empty($p['has_smtp_class'])) echo '<span class="won1-badge alert" style="background:#f8bbd0;color:#880e4f;">SMTP</span>';
            if (!empty($p['has_swiftmailer'])) echo '<span class="won1-badge alert" style="background:#f8bbd0;color:#880e4f;">SwiftMailer</span>';
            if (!empty($p['has_mail_extended'])) echo '<span class="won1-badge alert" style="background:#f8bbd0;color:#880e4f;">Mail Ext</span>';
            if (!empty($p['has_mail_any'])) echo '<span class="won1-badge alert" style="background:#f8bbd0;color:#880e4f;">Mail Any</span>';
            if (!empty($p['has_sendmail'])) echo '<span class="won1-badge alert" style="background:#f8bbd0;color:#880e4f;">Sendmail</span>';
            if ($any) echo '<span class="won1-badge rewritten">' . esc_html__('Rewritten', 'wondalizer-external-firewall') . '</span>';
            echo '<span class="spinner" style="float:none;margin-top:0;"></span>';
            echo '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }

    public static function processNext() {
        if (!class_exists('Won2_Scan')) {
            wp_send_json_success(['processed' => 0]);
            return;
        }
        $scan = new Won2_Scan();
        if (method_exists($scan, 'process_next_batch')) {
            $scan->process_next_batch();
            $count = method_exists($scan, 'get_last_processed_count') ? $scan->get_last_processed_count() : 0;
        } else {
            $count = 0;
        }
        wp_send_json_success(['processed' => $count]);
    }

    public static function bulk_btn($action, $type, $label, $tab = '') {
        ?><form method="post" style="display:inline;">
                <?php wp_nonce_field('won2_action', 'won2_nonce'); ?><input type="hidden" name="won2_action" value="<?php echo esc_attr($action); ?>"><?php if ($tab) : ?><input type="hidden" name="won1_tab" value="<?php echo esc_attr($tab); ?>"><?php endif; ?><button type="submit" class="button won1-btn <?php echo esc_attr($type); ?>"><?php echo esc_html($label); ?></button></form><?php
    }

    private static function maybe_load_renderers() {
        if (!is_admin()) return;

        $dir = WON2_DIR . 'includes/render/';
        if (!is_dir($dir)) return;

        $files = [
            'class-render-header.php',
            'class-render-roster.php',
            'class-render-cron.php',
            'class-render-settings.php',
            'class-render-logs.php',
            'class-render-about.php',
        ];
        foreach ($files as $f) {
            $path = $dir . $f;
            if (file_exists($path)) require_once $path;
        }
    }

    public static function render_page() {
        if (!current_user_can('manage_options')) return;

        self::maybe_load_renderers();

        $roster = [];
        $error_msg = '';
        try {
            if (class_exists('Won2_Admin_Roster')) {
                $roster = Won2_Admin_Roster::get_plugin_roster();
            } else {
                $error_msg = 'Admin Roster class not loaded.';
            }
        } catch (\Throwable $e) {
            $error_msg = 'Roster error: ' . $e->getMessage();
        }

        if (empty($roster) && empty($error_msg)) {
            $error_msg = __('No extensions found. Ensure you have plugins or themes installed.', 'wondalizer-external-firewall');
        }

        $settings = wp_parse_args(get_option('won2_firewall_settings', []), [
            'rw_curl'=>true,'rw_sock'=>true,'rw_mail'=>true,'logging_enabled'=>true,'http_firewall_enabled'=>false,
            'curl_cache_enabled'=>false,'block_recaptcha'=>false,
            'cron_firewall_enabled'=>false,'cron_block_by_default'=>false,
            'ultimate_scan_enabled'=>false,
        ]);

        $core = array_filter($roster, function($p){ return $p['is_core']; });
        $themes = array_filter($roster, function($p){ return $p['type'] === 'theme'; });
        $regular = array_filter($roster, function($p){ return !$p['is_core'] && $p['type'] !== 'theme'; });

        $http_on = !empty($settings['http_firewall_enabled']);
        $http_fw_on = $http_on;
        $logging_on = !empty($settings['logging_enabled']);
        $curl_on = !empty($settings['curl_cache_enabled']);
        $cron_on = !empty($settings['cron_firewall_enabled']);

        $can_rewrite = $curl_on && defined('WON2_MU_ACTIVE');

        $log_stats = Won2_Admin_Roster::get_log_stats();
        $total_http = (int) $log_stats['http_logs'];
        $total_http_blocked = (int) $log_stats['http_blocked'];
        $total_email = (int) $log_stats['email_logs'];
        $total_email_blocked = (int) $log_stats['email_blocked'];

        $obs_items = array_filter($roster, function($p){ return !empty($p['has_obfuscated']); });
        $total_obs = count($obs_items);

        $log_counts = Won2_Admin_Roster::get_log_counts_by_folder();

        if (class_exists('Won2_Render_Header')) {
            Won2_Render_Header::output($settings, $total_http, $total_http_blocked, $total_email, $total_email_blocked, $total_obs, $http_on, $cron_on, $logging_on, $curl_on, $http_fw_on, $error_msg);
        }

        if (class_exists('Won2_Render_Roster')) {
            Won2_Render_Roster::output($roster, $core, $themes, $regular, $settings, $can_rewrite, $log_counts, $error_msg);
        }

        if (class_exists('Won2_Render_Cron')) {
            Won2_Render_Cron::output($settings);
        }

        if (class_exists('Won2_Render_Settings')) {
            Won2_Render_Settings::output($settings);
        }

        if (class_exists('Won2_Render_Logs')) {
            Won2_Render_Logs::output($settings);
        }

        if (class_exists('Won2_Render_About')) {
            Won2_Render_About::output();
        }

        if (class_exists('Won2_Render_Footer')) {
            Won2_Render_Footer::output();
        }
    }

}
}