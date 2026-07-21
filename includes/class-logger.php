<?php
/**
 * Wondalizer External Firewall — Logger (v8.1.8)
 * Circuit breaker, transient fallbacks, batch operations, robust table handling.
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Logger')) {
class Won2_Logger {
    private static $instance = null;
    private static $table_name = null;
    private static $circuit_open = false;
    private static $circuit_time = 0;
    private static $batch = [];
    private static $batch_size = 50;
    private static $settings = null;

    public static function init() {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        global $wpdb;
        self::$table_name = $wpdb->prefix . 'won2_logs';
        add_action('shutdown', [$this, 'flush']);
    }

    public static function get_settings() {
        if (self::$settings === null) {
            self::$settings = wp_parse_args(get_option('won2_firewall_settings', []), [
                'logging_enabled' => true,
                'log_http_blocked' => true,
                'log_http_allowed' => false,
                'log_email_blocked' => true,
                'log_email_allowed' => true,
                'log_internal_http' => false,
            ]);
        }
        return self::$settings;
    }

    public static function refresh_settings() {
        self::$settings = null;
    }


    public function ensure_table() {
        if (self::$circuit_open && (time() - self::$circuit_time) < 10) return false;

        static $table_checked = false;
        if ($table_checked) return true;

        global $wpdb;

        $cached = wp_cache_get('won1_table_exists', 'won2');
        if (false !== $cached) {
            $table_checked = true;
            return (bool) $cached;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $table_exists = $wpdb->get_var($wpdb->prepare(
            "SHOW TABLES LIKE %s",
            self::$table_name
        )) === self::$table_name;

        wp_cache_set('won1_table_exists', (int) $table_exists, 'won2', 300);

        if (!$table_exists) {
            $charset = $wpdb->get_charset_collate();

            $sql = "CREATE TABLE IF NOT EXISTS " . self::$table_name . " (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                type varchar(20) NOT NULL DEFAULT 'http',
                url text DEFAULT NULL,
                host varchar(255) DEFAULT NULL,
                status varchar(20) NOT NULL DEFAULT 'ALLOWED',
                reason varchar(50) DEFAULT NULL,
                source_type varchar(20) DEFAULT NULL,
                source_name varchar(100) DEFAULT NULL,
                source_folder varchar(100) DEFAULT NULL,
                source_file varchar(255) DEFAULT NULL,
                blocked tinyint(1) NOT NULL DEFAULT 0,
                same_site tinyint(1) NOT NULL DEFAULT 0,
                created_at datetime DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY  (id),
                KEY type_status  (type,status),
                KEY created_at  (created_at),
                KEY host  (host(100))
            ) " . $charset . ";";

            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
            $wpdb->suppress_errors(true);
            dbDelta($sql);
            $wpdb->suppress_errors(false);
        }

        $table_checked = true;
        return true;
    }

    public function log($type, $url, $host, $status, $reason, $source, $blocked, $same_site = false) {
        if (!is_array($source)) {
            $source = [];
        }

        $settings = $this->get_settings();
        if (empty($settings['logging_enabled'])) return;

        $this->ensure_table();

        if ($type === 'http' && $status === 'BLOCKED' && empty($settings['log_http_blocked'])) return;
        if ($type === 'http' && $status === 'ALLOWED' && empty($settings['log_http_allowed'])) return;
        if ($type === 'email' && $status === 'BLOCKED' && empty($settings['log_email_blocked'])) return;
        if ($type === 'email' && $status === 'ALLOWED' && empty($settings['log_email_allowed'])) return;

        if (self::$circuit_open && (time() - self::$circuit_time) < 10) {
            $this->fallback_log($type, $url, $host, $status, $reason, $blocked, $source);
            return;
        }

        self::$batch[] = [
            'type' => $type, 'url' => $url, 'host' => $host, 'status' => $status,
            'reason' => $reason, 'source_type' => $source['type'] ?? null,
            'source_name' => $source['name'] ?? null, 'source_folder' => $source['folder'] ?? null,
            'source_file' => $source['file'] ?? null, 'blocked' => $blocked ? 1 : 0,
            'same_site' => $same_site ? 1 : 0,
            'created_at' => current_time('mysql'),
        ];

        if (count(self::$batch) >= self::$batch_size) {
            $this->flush_batch();
        }
    }

    public function log_direct($url, $host, $status, $blocked, $reason, $source, $same_site = false) {
        $this->log('http', $url, $host, $status, $reason, $source, $blocked, $same_site);
        $this->flush_batch();
    }

    public function trace($message) {
        $this->log('trace', $message, 'localhost', 'INFO', 'trace', ['type'=>'plugin','name'=>'Wondalizer External Firewall','folder'=>'wondalizer-external-firewall','file'=>''], false);
    }

    public function flush() {
        $this->flush_batch();
    }

    private function flush_batch() {
        if (empty(self::$batch)) return;

        $this->ensure_table();

        if (self::$circuit_open && (time() - self::$circuit_time) < 10) {
            foreach (self::$batch as $entry) {
                $this->fallback_log($entry['type'], $entry['url'], $entry['host'], $entry['status'], $entry['reason'], $entry['blocked'], ['type'=>$entry['source_type'],'name'=>$entry['source_name'],'folder'=>$entry['source_folder'],'file'=>$entry['source_file']]);
            }
            self::$batch = [];
            return;
        }

        global $wpdb;
        $wpdb->suppress_errors(true);

        // Build batch INSERT for performance
        $values = [];
        $placeholders = [];
        foreach (self::$batch as $entry) {
            $values[] = $entry['type'];
            $values[] = $entry['url'];
            $values[] = $entry['host'];
            $values[] = $entry['status'];
            $values[] = $entry['reason'];
            $values[] = $entry['source_type'];
            $values[] = $entry['source_name'];
            $values[] = $entry['source_folder'];
            $values[] = $entry['source_file'];
            $values[] = $entry['blocked'];
            $values[] = $entry['same_site'];
            $values[] = $entry['created_at'];
            $placeholders[] = "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%d,%d,%s)";
        }

        $table = self::$table_name;
        $sql = "INSERT INTO `{$table}` (type,url,host,status,reason,source_type,source_name,source_folder,source_file,blocked,same_site,created_at) VALUES " . implode(',', $placeholders);

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter
        $result = $wpdb->query($wpdb->prepare($sql, $values));

        if ($result === false) {
            self::$circuit_open = true;
            self::$circuit_time = time();
            // Fallback: log each entry individually
            foreach (self::$batch as $entry) {
                $this->fallback_log($entry['type'], $entry['url'], $entry['host'], $entry['status'], $entry['reason'], $entry['blocked'], ['type'=>$entry['source_type'],'name'=>$entry['source_name'],'folder'=>$entry['source_folder'],'file'=>$entry['source_file']]);
            }
        }

        self::$batch = [];
        $wpdb->suppress_errors(false);
    }

    private function fallback_log($type, $url, $host, $status, $reason, $blocked, $source) {
        if (!is_array($source)) {
            $source = [];
        }
        $key = 'won1_fallback_' . md5($type . $url . $host . time());
        set_transient($key, [
            'type' => $type, 'url' => $url, 'host' => $host, 'status' => $status,
            'reason' => $reason, 'blocked' => $blocked, 'time' => time(),
            'source_type' => $source['type'] ?? '',
            'source_name' => $source['name'] ?? '',
            'source_folder' => $source['folder'] ?? '',
            'source_file' => $source['file'] ?? '',
        ], HOUR_IN_SECONDS);
    }

    public function cleanup($days = 30) {
        if (self::$circuit_open && (time() - self::$circuit_time) < 10) return;

        // Only rate-limit automatic cleanup; manual clear-all (days <= 0) should always run.
        if ($days > 0) {
            $last_cleanup = get_transient('won1_last_cleanup');
            if ($last_cleanup) return;
            set_transient('won1_last_cleanup', time(), 60);
        }

        global $wpdb;
        if ($days <= 0) {
            $table = self::$table_name;
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from $wpdb->prefix (safe site config).
            $wpdb->query("DELETE FROM `{$table}`");
        } else {
            $cutoff = gmdate('Y-m-d H:i:s', strtotime("-{$days} days"));
            $table = self::$table_name;
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from $wpdb->prefix (safe site config).
            $wpdb->query($wpdb->prepare("DELETE FROM `{$table}` WHERE created_at < %s", $cutoff));
        }
    }

    public function get_stats() {
        if (self::$circuit_open && (time() - self::$circuit_time) < 10) {
            return ['total' => 0, 'blocked' => 0, 'http' => 0, 'email' => 0];
        }

        $cached = wp_cache_get('won1_log_stats', 'won2');
        if (is_array($cached)) {
            return $cached;
        }

        global $wpdb;
        $this->ensure_table();
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $table = self::$table_name;
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from $wpdb->prefix (safe site config).
        $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$table}` WHERE 1 = 1");
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $table = self::$table_name;
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from $wpdb->prefix (safe site config).
        $blocked = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `{$table}` WHERE blocked = %d", 1));
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $table = self::$table_name;
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from $wpdb->prefix (safe site config).
        $http = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `{$table}` WHERE type = %s", 'http'));
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $table = self::$table_name;
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from $wpdb->prefix (safe site config).
        $email = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `{$table}` WHERE type = %s", 'email'));
        
        $stats = ['total' => $total, 'blocked' => $blocked, 'http' => $http, 'email' => $email];
        wp_cache_set('won1_log_stats', $stats, 'won2', 30);
        return $stats;
    }

    public function get_recent($limit = 50, $type = null) {
        if (self::$circuit_open && (time() - self::$circuit_time) < 60) return [];

        $cache_key = 'won1_recent_' . (int) $limit . '_' . ($type ? sanitize_key($type) : 'all');
        $cached = wp_cache_get($cache_key, 'won2');
        if (is_array($cached)) {
            return $cached;
        }

        global $wpdb;
        $this->ensure_table();
        $safe_limit = (int) $limit;
        if ($type) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
            $table = self::$table_name;
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from $wpdb->prefix (safe site config).
            $results = $wpdb->get_results($wpdb->prepare("SELECT * FROM `{$table}` WHERE type = %s ORDER BY id DESC LIMIT %d", $type, $safe_limit), ARRAY_A);
        } else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
            $table = self::$table_name;
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from $wpdb->prefix (safe site config).
            $results = $wpdb->get_results($wpdb->prepare("SELECT * FROM `{$table}` WHERE type IN ('http', 'email') ORDER BY id DESC LIMIT %d", $safe_limit), ARRAY_A);
        }
        wp_cache_set($cache_key, $results, 'won2', 10);
        return $results;
    }
}
}