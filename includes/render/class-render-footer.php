<?php
/**
 * Wondalizer External Firewall — Render: Footer
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Render_Footer')) {
class Won2_Render_Footer {
    public static function output() {
        ?>
        <div id="won2-domain-modal" class="won1-domain-modal" style="display:none;position:fixed;z-index:100000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,0.6);">
            <div class="won1-domain-modal-content" style="background:#fff;margin:8% auto;padding:25px;border:none;width:90%;max-width:600px;max-height:80vh;overflow-y:auto;border-radius:6px;box-shadow:0 5px 25px rgba(0,0,0,0.2);">
                <span class="won1-domain-modal-close" onclick="closeDomainModal()" style="color:#aaa;float:right;font-size:28px;font-weight:bold;cursor:pointer;transition:color 0.2s;">&times;</span>
                <h2 style="margin-top:0; border-bottom:1px solid #eee; padding-bottom:10px;"><?php esc_html_e('Manage Allowed HTTP Domains', 'wondalizer-external-firewall'); ?></h2>
                <div id="domain-modal-body" style="padding-top:10px;"><?php esc_html_e('Loading...', 'wondalizer-external-firewall'); ?></div>
            </div>
        </div>
        <?php
        echo '</div>'; // close .wrap
    }
}
}
