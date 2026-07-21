<?php
/**
 * Wondalizer External Firewall — Admin Init (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Admin_Init')) {
class Won2_Admin_Init {
    private static $instance = null;
    private static $page_hook = null;

    public static function init($args = null) {
        if (self::$instance === null) self::$instance = new self($args);
        return self::$instance;
    }

    private function __construct($args = null) {
        add_action('admin_menu', [$this, 'add_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
        add_action('wp_dashboard_setup', [$this, 'add_dashboard_widget']);
    }

    public function add_menu() {
        self::$page_hook = add_menu_page(
            __('External Firewall', 'wondalizer-external-firewall'),
            __('External Firewall', 'wondalizer-external-firewall'),
            'manage_options',
            WON2_SLUG,
            ['Won2_Admin_Render', 'render_page'],
            'dashicons-shield',
            80
        );
    }

    public function enqueue_assets($hook) {
        if (empty($hook) || strpos($hook, WON2_SLUG) === false) {
            return;
        }

        wp_enqueue_style('won2-admin-css', WON2_ASSETS_URL . 'admin.css', [], WON2_VERSION);

        $js_path = WON2_DIR . 'assets/admin.js';
        $handle = 'won2-admin-js';

        if (file_exists($js_path)) {
            wp_enqueue_script($handle, WON2_ASSETS_URL . 'admin.js', ['jquery'], WON2_VERSION, true);
        } else {
            $handle = 'jquery';
            wp_enqueue_script('jquery');
        }

        wp_localize_script($handle, 'won1_ajax', [
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce'   => wp_create_nonce('won2_ajax'),
        ]);
    }

    public function add_dashboard_widget() {
        wp_add_dashboard_widget(
            'won2_dashboard',
            __('Wondalizer Firewall', 'wondalizer-external-firewall'),
            [$this, 'render_dashboard_widget']
        );
    }

    public function render_dashboard_widget() {
        $stats = Won2_Logger::init()->get_stats();
        echo '<div class="won1-dashboard-widget">';
        echo '<p><strong>' . esc_html__('HTTP Requests:', 'wondalizer-external-firewall') . '</strong> ' . esc_html($stats['http']) . '</p>';
        echo '<p><strong>' . esc_html__('Blocked:', 'wondalizer-external-firewall') . '</strong> ' . esc_html($stats['blocked']) . '</p>';
        echo '<p><strong>' . esc_html__('Email Logs:', 'wondalizer-external-firewall') . '</strong> ' . esc_html($stats['email']) . '</p>';
        echo '<p><a href="' . esc_url(admin_url('admin.php?page=' . WON2_SLUG)) . '">' . esc_html__('View Full Report', 'wondalizer-external-firewall') . '</a></p>';
        echo '</div>';
    }
}
}