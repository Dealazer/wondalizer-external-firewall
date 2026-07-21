<?php
/**
 * Wondalizer External Firewall — Source Tracer (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Source')) {
class Won2_Source {
    private static $instance = null;

    public static function init() {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }

    public function trace($depth = 20) {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, $depth + 3);
        $source = ['type' => 'unknown', 'name' => 'unknown', 'folder' => '', 'file' => ''];
        $plugin_dir = rtrim(str_replace('\\', '/', WP_PLUGIN_DIR), '/');
        $mu_dir = rtrim(str_replace('\\', '/', WPMU_PLUGIN_DIR), '/');
        $theme_dir = rtrim(str_replace('\\', '/', get_theme_root()), '/');
        $fw_dir = rtrim(str_replace('\\', '/', WON2_DIR), '/');
        $core_fallback = null;
        $mu_guard_file = 'wondalizer-fw-curl-guard.php';
        $plugin_candidates = [];

        foreach ($trace as $frame) {
            if (empty($frame['file'])) continue;
            $file = str_replace('\\', '/', $frame['file']);
            $file_basename = basename($file);

            if (strpos($file, $fw_dir) === 0) continue;
            if ($file_basename === $mu_guard_file) continue;

            if (strpos($file, $plugin_dir . '/') === 0) {
                $rel = substr($file, strlen($plugin_dir) + 1);
                $parts = explode('/', $rel);
                $folder = strtolower($parts[0]);
                if (!empty($folder)) {
                    $plugin_candidates[$folder] = [
                        'type' => 'plugin',
                        'folder' => $folder,
                        'name' => $folder,
                        'file' => $rel,
                    ];
                }
            }
            if (strpos($file, $mu_dir . '/') === 0) {
                $rel = substr($file, strlen($mu_dir) + 1);
                // Match the roster naming: top-level MU files are listed as
                // 'mu-<basename>' (no .php); subdirectory MU code keeps its folder.
                if (strpos($rel, '/') === false) {
                    $folder = 'mu-' . strtolower(sanitize_file_name(basename($rel, '.php')));
                } else {
                    $parts = explode('/', $rel);
                    $folder = strtolower($parts[0]);
                }
                if (!empty($folder)) {
                    $plugin_candidates[$folder] = [
                        'type' => 'mu-plugin',
                        'folder' => $folder,
                        'name' => $folder,
                        'file' => $rel,
                    ];
                }
            }
            if (strpos($file, $theme_dir . '/') === 0) {
                $rel = substr($file, strlen($theme_dir) + 1);
                $parts = explode('/', $rel);
                $folder = strtolower($parts[0]);
                if (!empty($folder)) {
                    $plugin_candidates[$folder] = [
                        'type' => 'theme',
                        'folder' => $folder,
                        'name' => $folder,
                        'file' => $rel,
                    ];
                }
            }

            $normalized_abspath = rtrim(str_replace('\\', '/', ABSPATH), '/');
            if (strpos($file, $normalized_abspath . '/wp-admin/') === 0) {
                if ($core_fallback === null) {
                    $core_fallback = [
                        'type'   => 'core',
                        'name'   => 'WordPress Core',
                        'folder' => 'wordpress-core',
                        'file'   => substr($file, strlen($normalized_abspath) + 1),
                    ];
                }
                continue;
            }
            if (strpos($file, $normalized_abspath . '/wp-includes/') === 0) {
                if ($core_fallback === null) {
                    $core_fallback = [
                        'type'   => 'core',
                        'name'   => 'WordPress Core',
                        'folder' => 'wordpress-core',
                        'file'   => substr($file, strlen($normalized_abspath) + 1),
                    ];
                }
                continue;
            }
        }

        if (!empty($plugin_candidates)) {
            $first = reset($plugin_candidates);
            return $first;
        }

        if ($core_fallback !== null) {
            return $core_fallback;
        }

        return $source;
    }

    public function trace_deep() {
        return $this->trace(500);
    }

    public function trace_for_firewall() {
        return $this->trace(100);
    }
}
}