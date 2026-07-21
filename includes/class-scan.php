<?php
/**
 * Wondalizer External Firewall — Scan & Rewrite Engine (v8.1.8)
 */

if (!defined('ABSPATH')) exit;

if (!class_exists('Won2_Scan')) {
class Won2_Scan {
    const SCAN_VERSION = '8.1.8';

    public static function is_protected_folder($folder) {
        $folder = strtolower($folder);
        return (strpos($folder, 'wondalizer-external-firewall') !== false || strpos($folder, 'wondalizer-fw') !== false);
    }
    private static $backup_suffix = '.wondalizer-bak';
    private static $memory_cache = null;
    private static $cache_changed = false;
    private $last_processed_count = 0;

    /** Known core domains — used for modal display instead of scanning 2000+ files */
    const CORE_DOMAINS = [
        'api.wordpress.org',
        'downloads.wordpress.org',
        'wordpress.org',
        's.w.org',
        'ps.w.org',
        'core.trac.wordpress.org',
        'meta.trac.wordpress.org',
        'planet.wordpress.org',
        'jetpack.wordpress.com',
        'public-api.wordpress.com',
        'stats.wordpress.com',
    ];

    /** Domains that are clearly documentation/examples and never real network calls */
    const FALSE_POSITIVE_DOMAINS = [
        'example.com', 'example.org', 'example.net',
        'localhost', '127.0.0.1', '0.0.0.0',
        'your-domain.com', 'yourdomain.com', 'domain.com',
        'mysite.com', 'my-site.com', 'test.com', 'test.org',
        'demo.com', 'demo.org', 'sample.com', 'sample.org',
        'placeholder.com', 'placeholder.org',
        'foo.com', 'bar.com', 'baz.com',
        'example', 'localhost',
    ];

    public function __construct() {
        if (self::$memory_cache === null) {
            self::$memory_cache = (array) get_option('won2_scan_cache_v2', []);
        }
    }

    private function update_cache($key, $value) {
        self::$memory_cache[$key] = $value;
        self::$cache_changed = true;
    }

    public function save_cache() {
        if (self::$cache_changed) {
            update_option('won2_scan_cache_v2', self::$memory_cache, false);
            self::$cache_changed = false;
        }
    }

    public static function clear_scan_cache() {
        delete_option('won2_scan_cache_v2');
        self::$memory_cache = [];
        self::$cache_changed = false;
    }

    /**
     * Safety-net filter for old cached domains.
     */
    public static function filter_display_domains($folder, $domains) {
        return is_array($domains) ? array_values(array_unique(array_filter($domains))) : [];
    }

    private static function is_false_positive($domain) {
        $d = strtolower($domain);
        foreach (self::FALSE_POSITIVE_DOMAINS as $fp) {
            if ($d === $fp || substr($d, -strlen('.' . $fp)) === '.' . $fp) {
                return true;
            }
        }
        return false;
    }

    private static function get_extension_path_static($folder) {
        if ($folder === 'wordpress-core' || $folder === 'wp-core' || $folder === 'core') {
            return false;
        }
        $paths = [];
        if (defined("WP_PLUGIN_DIR")) $paths[] = WP_PLUGIN_DIR . "/" . $folder;
        if (defined("WPMU_PLUGIN_DIR")) $paths[] = WPMU_PLUGIN_DIR . "/" . $folder;
        if (function_exists("get_theme_root")) $paths[] = get_theme_root() . "/" . $folder;
        if (defined("ABSPATH")) {
            $paths[] = ABSPATH . "wp-admin/" . $folder;
            $paths[] = ABSPATH . "wp-includes/" . $folder;
        }
        foreach ($paths as $p) {
            if (is_dir($p)) return $p;
        }
        // Must-use plugins are registered in the roster as "mu-<name>" and are
        // usually single files (not directories) inside the mu-plugins folder.
        if (strpos($folder, 'mu-') === 0 && defined('WPMU_PLUGIN_DIR')) {
            $mu_base = substr($folder, 3);
            $mu_candidates = [WPMU_PLUGIN_DIR . "/" . $mu_base, WPMU_PLUGIN_DIR . "/" . $mu_base . '.php'];
            foreach ($mu_candidates as $mu_p) {
                if (is_dir($mu_p) || is_file($mu_p)) return $mu_p;
            }
        }
        return false;
    }

    private static function get_all_files_static($dir, $limit = 100) {
        $files = [];
        // A must-use plugin can resolve to a single file rather than a directory.
        if (is_file($dir) && is_readable($dir) && strtolower(pathinfo($dir, PATHINFO_EXTENSION)) === 'php') return [$dir];
        if (!is_dir($dir) || !is_readable($dir)) return $files;
        if (function_exists('get_option')) {
            $settings = get_option('won2_firewall_settings', []);
            if (!empty($settings['ultimate_scan_enabled'])) {
                $limit = 1000;
            }
        }

        $mem_limit = ini_get('memory_limit');
        $limit_bytes = 64 * 1024 * 1024; // 64MB default safe fallback
        if ($mem_limit && $mem_limit !== '-1') {
            $unit = strtolower(substr($mem_limit, -1));
            $val = (int)$mem_limit;
            if ($unit === 'g') $limit_bytes = $val * 1024 * 1024 * 1024;
            elseif ($unit === 'm') $limit_bytes = $val * 1024 * 1024;
            elseif ($unit === 'k') $limit_bytes = $val * 1024;
            else $limit_bytes = $val;
        }
        $safe_limit = $limit_bytes * 0.75; // Use up to 75% of available memory limit safely
        if (memory_get_usage(true) > $safe_limit) return $files;

        try {
            $directory = new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS);
            $filter = new RecursiveCallbackFilterIterator($directory, function ($current, $key, $iterator) {
                if ($iterator->hasChildren()) {
                    $skip = ['node_modules','.git','.github','languages','lang','assets','images','img','css','js','fonts','tests','docs','cache','sass','scss','dist','build'];
                    if (in_array(strtolower($current->getFilename()), $skip, true)) return false;
                    return true;
                }
                return strtolower(pathinfo($current->getFilename(), PATHINFO_EXTENSION)) === 'php';
            });
            $iterator = new RecursiveIteratorIterator($filter);
            foreach ($iterator as $file) {
                $files[] = $file->getPathname();
                if (count($files) >= $limit) break;
            }
        } catch (\Throwable $e) {
            $files = @glob($dir . "/*.php");
            if (!is_array($files)) $files = [];
        }
        return $files;
    }

    private static function strip_comments_static($code) {
        $tokens = @token_get_all($code);
        if ($tokens === false || empty($tokens)) {
            $code = preg_replace('#/\*.*?\*/#s', '', $code);
            $code = preg_replace('#(^\s*)//.*$#m', '$1', $code);
            $code = preg_replace('#(^\s*)\#.*$#m', '$1', $code);
            return $code;
        }
        $clean = '';
        foreach ($tokens as $token) {
            if (is_array($token)) {
                if ($token[0] === T_COMMENT || $token[0] === T_DOC_COMMENT) continue;
                $clean .= $token[1];
            } else {
                $clean .= $token;
            }
        }
        return $clean;
    }

    private function strip_php_comments($code) {
        return self::strip_comments_static($code);
    }

    private function extract_all_domains($code) {
        $domains = [];
        $clean = $this->strip_php_comments($code);
        if (preg_match_all('#https?://([a-zA-Z0-9\-\.]+)#', $clean, $dm)) {
            foreach ($dm[1] as $d) {
                if (self::is_false_positive($d)) continue;
                if (!in_array($d, $domains, true)) $domains[] = $d;
            }
        }
        return $domains;
    }

    public function rewrite_plugin_files($folder, $method = 'all') {
        if ($this->is_protected_folder($folder)) {
            return ['success' => false, 'message' => 'Protected extension cannot be rewritten.', 'rewritten' => 0];
        }
        $types = [];
        if ($method === 'all') {
            $types = ['curl', 'sock', 'mail'];
        } else {
            $types = [$method];
        }
        $res = $this->rewrite_extension($folder, $types);
        if ($res['success']) {
            $rewritten = (array) get_option('won2_rewritten_plugins', []);
            if (!isset($rewritten[$folder]) || !is_array($rewritten[$folder])) {
                $rewritten[$folder] = [];
            }
            if ($method === 'all') {
                $rewritten[$folder] = ['curl' => true, 'sock' => true, 'mail' => true];
            } else {
                $rewritten[$folder][$method] = true;
            }
            update_option('won2_rewritten_plugins', $rewritten);
            return ['success' => true, 'message' => sprintf('Successfully rewritten %d file(s).', $res['rewritten']), 'data' => $res];
        }
        return ['success' => false, 'message' => $res['message'] ?? 'Rewriting failed.'];
    }

    public function restore_plugin_files($folder, $method = 'all') {
        $res = $this->restore_extension($folder);
        if ($res['success']) {
            $rewritten = (array) get_option('won2_rewritten_plugins', []);
            if ($method === 'all') {
                unset($rewritten[$folder]);
            } else {
                if (isset($rewritten[$folder][$method])) {
                    unset($rewritten[$folder][$method]);
                }
                if (empty($rewritten[$folder])) {
                    unset($rewritten[$folder]);
                }
            }
            update_option('won2_rewritten_plugins', $rewritten);
            return ['success' => true, 'message' => sprintf('Successfully restored %d file(s).', $res['restored']), 'data' => $res];
        }
        return ['success' => false, 'message' => $res['message'] ?? 'Restoring failed.'];
    }

    public function scan_plugin($folder, $force = false) {
        $start_time = microtime(true);
        $ck = md5($folder);
        if (!$force && isset(self::$memory_cache[$ck]) && is_array(self::$memory_cache[$ck])
            && (time() - self::$memory_cache[$ck]['time']) < DAY_IN_SECONDS * 3
            && isset(self::$memory_cache[$ck]['version'])
            && self::$memory_cache[$ck]['version'] === self::SCAN_VERSION) {
            return self::$memory_cache[$ck]['data'];
        }

        $result = [
            'domains' => [], 'has_curl' => false, 'has_curl_multi' => false, 'has_curl_share' => false,
            'has_curl_indirect' => false, 'has_curl_class' => false, 'has_curl_namespace' => false,
            'has_fsockopen' => false, 'has_socket_raw' => false, 'has_stream_socket' => false,
            'has_php_mail' => false, 'has_wp_mail' => false, 'has_phpmailer' => false,
            'has_smtp_class' => false, 'has_swiftmailer' => false, 'has_wp_http' => false,
            'has_wp_http_api' => false, 'has_guzzle' => false, 'has_requests_lib' => false,
            'has_http_client' => false, 'has_rest_api' => false, 'has_xmlrpc' => false,
            'has_soap' => false, 'has_ftp' => false, 'has_sftp' => false, 'has_ssh2' => false,
            'has_obfuscated' => false, 'obs_score' => 0, 'obs_patterns' => [],
            'has_curl_file' => false, 'has_curl_easy' => false, 'has_curl_mime' => false, 'has_curl_form' => false,
            'has_curl_any' => false, 'has_curlopt' => false,
            'has_socket_extended' => false, 'has_stream_extended' => false, 'has_dns_lookup' => false,
            'has_socket_any' => false, 'has_stream_any' => false,
            'has_mail_extended' => false, 'has_mail_any' => false, 'has_sendmail' => false,
            'has_wp_http_any' => false, 'has_file_get_contents' => false, 'has_fopen_any' => false,
            'has_copy_any' => false, 'has_readfile_any' => false, 'has_file_any' => false,
            'has_wp_http_obj' => false, 'has_requests_obj' => false, 'has_symfony_http' => false,
            'has_laravel_http' => false, 'has_react_http' => false, 'has_amp_http' => false,
            'has_stream_select' => false, 'has_stream_socket_enable_crypto' => false, 'has_stream_socket_get_name' => false,
            'has_stream_socket_pair' => false, 'has_stream_socket_shutdown' => false, 'has_stream_context_default' => false,
            'has_stream_set_chunk_size' => false, 'has_proc_open_network' => false, 'has_popen_network' => false,
            'has_socket_addrinfo' => false, 'has_socket_cmsg_space' => false, 'has_socket_wsa' => false,
            'has_socket_set_nonblocking' => false, 'has_getprotobyname' => false, 'has_inet_pton' => false,
            'has_net_get_interfaces' => false, 'has_openssl_socket' => false, 'has_gethostbynamel' => false,
            'has_gethostname' => false, 'has_mailparse' => false, 'has_ezmlm_hash' => false,
            'has_email_class' => false, 'has_notification_send' => false, 'has_message_send' => false,
            'has_imap_open' => false, 'has_pop3_class' => false, 'has_nntp_class' => false,
            'has_smtp_port_config' => false, 'has_mail_server_config' => false, 'has_send_email_generic' => false,
            'has_mail_to_url' => false, 'has_wp_mail_smtp' => false, 'has_email_queue' => false,
            'has_soap' => false, 'has_ftp' => false, 'has_xmlrpc' => false, 'has_rest_api' => false,
            'curl_methods' => [], 'http_libraries' => [], 'detection_confidence' => 'low',
        ];

        if ($folder === 'wordpress-core' || $folder === 'wp-core' || $folder === 'core') {
            $result['domains'] = self::CORE_DOMAINS;
            $result['has_wp_http'] = true;
            $this->update_cache($ck, ['time' => time(), 'version' => self::SCAN_VERSION, 'data' => $result]);
            return $result;
        }

        $path = $this->get_extension_path($folder);
        if (!$path) {
            $this->update_cache($ck, ['time' => time(), 'version' => self::SCAN_VERSION, 'data' => $result]);
            return $result;
        }

        $files = $this->get_all_files($path, 50);
        $domains = []; $obs_found = []; $curl_methods = []; $http_libraries = [];

        $obs_pats = [
            'base64_decode' => '#base64_decode\s*\(#i',
            'eval' => '#(?<![a-zA-Z0-9_\$])eval\s*\(#i',
            'gzinflate' => '#gzinflate\s*\(#i',
            'str_rot13' => '#str_rot13\s*\(#i',
            'hex2bin' => '#hex2bin\s*\(#i',
            'assert' => '#assert\s*\(#i',
            'preg_replace_e' => '#preg_replace\s*\(\s*["\']\s*/[^/]*/[a-zA-Z]*e[a-zA-Z]*["\']#i',
            'create_function' => '#create_function\s*\(#i',
            'long_base64' => '#[A-Za-z0-9+/]{120,}#',
            'variable_call' => '#\$[a-zA-Z_]\w*\s*\(#',
            'file_get_php' => '#file_get_contents\s*\(\s*["\']php://#i',
            'call_user_func' => '#call_user_func(_array)?\s*\(#i',
            'func_get_args' => '#func_get_args\s*\(#i',
            'dynamic_include' => '#include(_once)?\s*\(\s*\$#i',
            'dynamic_require' => '#require(_once)?\s*\(\s*\$#i',
        ];

        $curl_patterns = [
            'curl_init' => '#(?<![a-zA-Z0-9_])curl_init\s*\(#i',
            'curl_setopt' => '#(?<![a-zA-Z0-9_])curl_setopt(_array)?\s*\(#i',
            'curl_exec' => '#(?<![a-zA-Z0-9_])curl_exec\s*\(#i',
            'curl_close' => '#(?<![a-zA-Z0-9_])curl_close\s*\(#i',
            'curl_multi' => '#(?<![a-zA-Z0-9_])curl_multi_[a-z0-9_]+\s*\(#i',
            'curl_share' => '#(?<![a-zA-Z0-9_])curl_share_[a-z0-9_]+\s*\(#i',
            'curl_version' => '#(?<![a-zA-Z0-9_])curl_version\s*\(#i',
            'curl_getinfo' => '#(?<![a-zA-Z0-9_])curl_getinfo\s*\(#i',
            'curl_error' => '#(?<![a-zA-Z0-9_])curl_(error|errno)\s*\(#i',
            'curl_reset' => '#(?<![a-zA-Z0-9_])curl_reset\s*\(#i',
            'curl_copy' => '#(?<![a-zA-Z0-9_])curl_copy_handle\s*\(#i',
            'curl_pause' => '#(?<![a-zA-Z0-9_])curl_pause\s*\(#i',
            'curl_upkeep' => '#(?<![a-zA-Z0-9_])curl_upkeep\s*\(#i',
            'curl_escape' => '#(?<![a-zA-Z0-9_])curl_escape\s*\(#i',
            'curl_unescape' => '#(?<![a-zA-Z0-9_])curl_unescape\s*\(#i',
            'curl_strerror' => '#(?<![a-zA-Z0-9_])curl_strerror\s*\(#i',
            'curl_file_create' => '#(?<![a-zA-Z0-9_])curl_file_create\s*\(#i',
            'curl_easy_init' => '#(?<![a-zA-Z0-9_])curl_easy_init\s*\(#i',
            'curl_easy_setopt' => '#(?<![a-zA-Z0-9_])curl_easy_setopt\s*\(#i',
            'curl_easy_exec' => '#(?<![a-zA-Z0-9_])curl_easy_exec\s*\(#i',
            'curl_easy_cleanup' => '#(?<![a-zA-Z0-9_])curl_easy_cleanup\s*\(#i',
            'curl_easy_getinfo' => '#(?<![a-zA-Z0-9_])curl_easy_getinfo\s*\(#i',
            'curl_easy_strerror' => '#(?<![a-zA-Z0-9_])curl_easy_strerror\s*\(#i',
            'curl_easy_reset' => '#(?<![a-zA-Z0-9_])curl_easy_reset\s*\(#i',
            'curl_easy_duphandle' => '#(?<![a-zA-Z0-9_])curl_easy_duphandle\s*\(#i',
            'curl_mime_init' => '#(?<![a-zA-Z0-9_])curl_mime_init\s*\(#i',
            'curl_mime_addpart' => '#(?<![a-zA-Z0-9_])curl_mime_addpart\s*\(#i',
            'curl_mime_filedata' => '#(?<![a-zA-Z0-9_])curl_mime_filedata\s*\(#i',
            'curl_mime_name' => '#(?<![a-zA-Z0-9_])curl_mime_name\s*\(#i',
            'curl_mime_data' => '#(?<![a-zA-Z0-9_])curl_mime_data\s*\(#i',
            'curl_formadd' => '#(?<![a-zA-Z0-9_])curl_formadd\s*\(#i',
            'curl_pushfunction' => '#(?<![a-zA-Z0-9_])curl_pushfunction\s*\(#i',
            'curl_any' => '#\bcurl_[a-zA-Z0-9_]{1,30}\b#i',
            'curlopt_any' => '#\bCURLOPT_[A-Z0-9_]{1,30}\b#i',
            'ns_curl' => '#\\curl_[a-z0-9_]+\s*\(#i',
            'var_curl' => '#\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*["\']https?://#i',
            'var_func_curl' => '#\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\']curl_init["\']#i',
            'cuf_curl' => '#call_user_func(_array)?\s*\(\s*["\']curl_#i',
            'guzzle' => '#(GuzzleHttp\\|new\s+Guzzle|Guzzle\s*::|Client\s*\(\s*\[)|use\s+GuzzleHttp#i',
            'requests_lib' => '#(Requests::|WpOrg\\Requests|new\s+Requests_|Requests_)|use\s+Requests#i',
            'wp_http_curl' => '#(WP_Http_Curl|wp_http_curl|class.*WP_Http_Curl)#i',
            'http_client' => '#(HttpClient|HTTP_Client|Http\\Client|new\s+HttpClient)#i',
            'wp_remote' => '#wp_remote_(get|post|request|head|retrieve_body)\s*\(#i',
            'wp_http_api' => '#(wp_remote_fopen|download_url|wp_oembed_get|wp_safe_remote)#i',
            'rest_api' => '#(wp_remote_post.*rest|wp_remote_post.*api|json_encode.*wp_remote|rest_ensure_response)#i',
            'woocommerce_api' => '#(WC_API|woocommerce.*api|wc_api_)#i',
            'stripe_sdk' => '#(Stripe\\|Stripe_\w+::|new\s+Stripe\\|Stripe\s*::)#i',
            'paypal_sdk' => '#(PayPal\\|PayPal_\w+::|new\s+PayPal\\|PayPal\s*::)#i',
            'mailchimp_api' => '#(Mailchimp|mailchimp.*api|mc_.*api|new\s+Mailchimp)#i',
            'elementor_api' => '#(elementor.*library|Elementor\\|template.*remote)#i',
            'gravity_webhook' => '#(gravity.*webhook|GF.*webhook|gform.*webhook)#i',
            'cf7_recaptcha' => '#(wpcf7.*recaptcha|cf7.*google|contact.*form.*7.*api)#i',
            'rankmath_api' => '#(rankmath.*api|RankMath\\|rank_math.*remote)#i',
            'yoast_api' => '#(yoast.*api|Yoast\\|wpseo.*remote)#i',
            'http_class' => '#(class\s+\w+.*Http|class\s+\w+.*Curl|class\s+\w+.*Request|extends\s+WP_Http)#i',
            'http_method' => '#(function\s+(get|post|put|delete|patch|head)\s*\(|public\s+function\s+(request|fetch|download|upload))#i',
            'stream_context' => '#(stream_context_create|stream_context_set_option|stream_socket_client)#i',
            'soap' => '#(new\s+SoapClient|SoapClient::|class.*SoapClient)#i',
            'ftp' => '#(ftp_(connect|login|get|put)|ssh2_(connect|auth|exec|sftp))#i',
            'xmlrpc' => '#(xmlrpc_(encode|decode|server)|IXR_Client|wp_xmlrpc)#i',
            'fgc_url' => '#file_get_contents\s*\(\s*["\']https?://#i',
            'fopen_url' => '#fopen\s*\(\s*["\']https?://#i',
            'readfile_url' => '#readfile\s*\(\s*["\']https?://#i',
            'get_headers' => '#get_headers\s*\(\s*["\']https?://#i',
            'parse_url_http' => '#parse_url\s*\(\s*\$.*http#i',
            'variable_function_call' => '#\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*["\']https?://#i',
            'variable_curl_string' => '#\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\']curl_init["\']#i',
            'call_user_func_curl' => '#call_user_func(_array)?\s*\(\s*["\']curl_#i',
            'func_get_arg_curl' => '#func_get_arg\s*\(.*curl#i',
            'array_map_curl' => '#array_map\s*\(.*curl#i',
            'array_walk_curl' => '#array_walk\s*\(.*curl#i',
            'array_filter_curl' => '#array_filter\s*\(.*curl#i',
            'usort_curl' => '#usort\s*\(.*curl#i',
            'uasort_curl' => '#uasort\s*\(.*curl#i',
            'uksort_curl' => '#uksort\s*\(.*curl#i',
            'array_reduce_curl' => '#array_reduce\s*\(.*curl#i',
            'preg_replace_callback_curl' => '#preg_replace_callback\s*\(.*curl#i',
            'register_shutdown_curl' => '#register_shutdown_function\s*\(.*curl#i',
            'spl_autoload_curl' => '#spl_autoload_register\s*\(.*curl#i',
            'set_error_handler_curl' => '#set_error_handler\s*\(.*curl#i',
            'set_exception_handler_curl' => '#set_exception_handler\s*\(.*curl#i',
            'ob_start_curl' => '#ob_start\s*\(.*curl#i',
            'header_register_callback_curl' => '#header_register_callback\s*\(.*curl#i',
            'fastcgi_finish_curl' => '#fastcgi_finish_request\s*\(.*curl#i',
            'ignore_user_abort_curl' => '#ignore_user_abort\s*\(.*curl#i',
            'wp_http_any' => '#\bwp_remote_[a-zA-Z0-9_]{1,30}\b#i',
            'wp_safe_remote_any' => '#\bwp_safe_remote_[a-zA-Z0-9_]{1,30}\b#i',
            'wp_http_obj' => '#new\s+WP_Http#i',
            'requests_obj' => '#new\s+Requests#i',
            'symfony_http' => '#Symfony\\\\Component\\\\HttpClient#i',
            'laravel_http' => '#Illuminate\\\\Http\\\\Client#i',
            'react_http' => '#React\\\\Http#i',
            'amp_http' => '#Amp\\\\Http#i',
            'file_get_contents_any' => '#\bfile_get_contents\b#i',
            'fopen_any' => '#\bfopen\b#i',
            'copy_any' => '#\bcopy\b#i',
            'readfile_any' => '#\breadfile\b#i',
            'file_any' => '#\bfile\b#i',
            'file_put_contents_any' => '#\bfile_put_contents\b#i',
            'fpassthru_any' => '#\bfpassthru\b#i',
            'stream_get_contents_any' => '#\bstream_get_contents\b#i',
            'stream_copy_any' => '#\bstream_copy_to_stream\b#i',
            'fsockopen' => '#(?<![a-zA-Z0-9_])fsockopen\s*\(#i',
            'pfsockopen' => '#(?<![a-zA-Z0-9_])pfsockopen\s*\(#i',
            'stream_socket' => '#(?<![a-zA-Z0-9_])stream_socket_(client|server|accept|recvfrom|sendto|connect)\s*\(#i',
            'socket_create' => '#(?<![a-zA-Z0-9_])socket_(create|connect|bind|listen|accept|send|recv|close|getopt|setopt)\s*\(#i',
            'stream_socket_extended' => '#(?<![a-zA-Z0-9_])stream_socket_(get_name|enable_crypto|shutdown|pair)\s*\(#i',
            'stream_extended' => '#(?<![a-zA-Z0-9_])stream_(set_timeout|set_blocking|set_write_buffer|set_read_buffer|context_set_params|context_get_params|context_get_options|get_meta_data|get_transports|filter_append)\s*\(#i',
            'socket_extended' => '#(?<![a-zA-Z0-9_])socket_(getpeername|getsockname|last_error|strerror|clear_error|set_block|set_nonblock|set_option|get_option|shutdown|write|read|recvfrom|sendto|create_listen|create_pair|import_stream|get_status|set_timeout|recvmsg|sendmsg)\s*\(#i',
            'dns_lookup' => '#(?<![a-zA-Z0-9_])(dns_get_record|gethostbyname|gethostbyaddr|checkdnsrr|getmxrr|dns_check_record)\s*\(#i',
            'socket_any' => '#\bsocket_[a-zA-Z0-9_]{1,30}\b#i',
            'stream_any' => '#\bstream_socket_[a-zA-Z0-9_]{1,30}\b#i',
            'phpmailer' => '#(new\s+PHPMailer|PHPMailer::|class.*PHPMailer|use\s+PHPMailer)#i',
            'swiftmailer' => '#(new\s+Swift_|Swift_\w+::|Swift_Mailer|use\s+Swift_)#i',
            'wp_mail' => '#(?<![a-zA-Z0-9_])wp_mail\s*\(#i',
            'php_mail' => '#(?<![a-zA-Z0-9_])mail\s*\(#i',
            'smtp_class' => '#(new\s+SMTP|SMTP::|class.*SMTP|use\s+SMTP)#i',
            'mb_send_mail' => '#(?<![a-zA-Z0-9_])mb_send_mail\s*\(#i',
            'imap_mail' => '#(?<![a-zA-Z0-9_])imap_mail\s*\(#i',
            'mail_filter' => '#(wp_mail_from|wp_mail_from_name|wp_mail_content_type|wp_mail_charset|phpmailer_init|wp_mail_failed)\s*\(#i',
            'mail_exec' => '#(exec|system|passthru|shell_exec|proc_open|popen)\s*\(.*mail|sendmail|msmtp|postfix#i',
            'zend_mail' => '#(Zend_Mail|Zend\\\\Mail|new\s+Zend_Mail)#i',
            'mail_mime' => '#(Mail_mime|Mail_RFC822|new\s+Mail_)#i',
            'mail_any' => '#\bmail_[a-zA-Z0-9_]{1,30}\b#i',
            'sendmail_direct' => '#(sendmail_path|sendmail\s+-|/usr/sbin/sendmail|/usr/bin/sendmail)\b#i',
            'msmtp_direct' => '#(msmtp|MSMTP)\b#i',
            'postfix_direct' => '#(postfix|POSTFIX)\b#i',
            'stream_select' => '#(?<![a-zA-Z0-9_])stream_select\s*\(#i',
            'stream_socket_enable_crypto' => '#(?<![a-zA-Z0-9_])stream_socket_enable_crypto\s*\(#i',
            'stream_socket_get_name' => '#(?<![a-zA-Z0-9_])stream_socket_get_name\s*\(#i',
            'stream_socket_pair' => '#(?<![a-zA-Z0-9_])stream_socket_pair\s*\(#i',
            'stream_socket_shutdown' => '#(?<![a-zA-Z0-9_])stream_socket_shutdown\s*\(#i',
            'stream_context_default' => '#(?<![a-zA-Z0-9_])stream_context_(get_default|set_default)\s*\(#i',
            'stream_set_chunk_size' => '#(?<![a-zA-Z0-9_])stream_set_chunk_size\s*\(#i',
            'proc_open_network' => '#(?<![a-zA-Z0-9_])proc_open\s*\(.*(pipe|socket|tcp|udp|ssl|tls|http|https|ftp|ssh)#i',
            'popen_network' => '#(?<![a-zA-Z0-9_])popen\s*\(.*(tcp|udp|ssl|tls|http|https|ftp|ssh|socket)#i',
            'socket_addrinfo' => '#(?<![a-zA-Z0-9_])socket_addrinfo_(bind|connect|explain|lookup)\s*\(#i',
            'socket_cmsg_space' => '#(?<![a-zA-Z0-9_])socket_cmsg_space\s*\(#i',
            'socket_wsa' => '#(?<![a-zA-Z0-9_])socket_wsaprotocol_info_(export|import|release)\s*\(#i',
            'socket_set_nonblocking' => '#(?<![a-zA-Z0-9_])socket_set_nonblock\s*\(#i',
            'getprotobyname' => '#(?<![a-zA-Z0-9_])(getprotobyname|getprotobynumber|getservbyname|getservbyport)\s*\(#i',
            'inet_pton' => '#(?<![a-zA-Z0-9_])(inet_pton|inet_ntop|ip2long|long2ip)\s*\(#i',
            'net_get_interfaces' => '#(?<![a-zA-Z0-9_])net_get_interfaces\s*\(#i',
            'openssl_socket' => '#(?<![a-zA-Z0-9_])openssl_(encrypt|decrypt|seal|open|sign|verify|csr_sign|pkcs7_sign|pkcs7_encrypt|cms_sign|cms_encrypt)\s*\(#i',
            'gethostbynamel' => '#(?<![a-zA-Z0-9_])gethostbynamel\s*\(#i',
            'gethostname' => '#(?<![a-zA-Z0-9_])gethostname\s*\(#i',
            'mailparse' => '#(?<![a-zA-Z0-9_])mailparse_(msg_create|msg_extract_part|msg_parse|msg_get_structure|rfc822_parse_addresses|stream_encode|determine_best_xfer_encoding)\s*\(#i',
            'ezmlm_hash' => '#(?<![a-zA-Z0-9_])ezmlm_hash\s*\(#i',
            'email_class' => '#(class\s+\w+.*Email|class\s+\w+.*Mailer|class\s+\w+.*Message|class\s+\w+.*Notification|class\s+\w+.*Newsletter)\s*\{#i',
            'notification_send' => '#(function\s+sendNotification|function\s+notify|function\s+alert|function\s+remind|function\s+announce)\s*\(#i',
            'message_send' => '#(function\s+sendMessage|function\s+deliverMessage|function\s+transmitMessage|function\s+relayMessage|function\s+forwardMessage|function\s+bounceMessage)\s*\(#i',
            'imap_open' => '#(?<![a-zA-Z0-9_])imap_(open|close|reopen|ping|check|mail_copy|mail_move|createmailbox|deletemailbox|renamemailbox|subscribe|unsubscribe|list|lsub|fetch_overview|fetchheader|fetchbody|fetchstructure|body|header|headerinfo|rfc822_parse_headers|rfc822_write_address|utf8|utf7_decode|utf7_encode|mime_header_decode|base64|qprint|8bit|binary|mail_compose|search|sort|status|num_msg|num_recent|uid|msgno|alerts|errors|last_error|timeout|get_quota|get_quotaroot|set_quota|setacl|getacl|listmailbox|listsubscribed|getmailboxes|getsubscribed|thread|gc)\s*\(#i',
            'pop3_class' => '#(class\s+\w+.*POP3|class\s+\w+.*Pop3|new\s+POP3|pop3_(connect|login|get|stat|list|retr|dele|quit|noop|rset|top|uidl|user|pass|apop|auth))\s*\(#i',
            'nntp_class' => '#(class\s+\w+.*NNTP|class\s+\w+.*Nntp|new\s+NNTP|nntp_(connect|login|get|post|quit|noop|group|list|article|head|body|stat|next|last|search|xhdr|xover|xzver|xpat|xthread|xreference|xversion|xindex|xname|xactive|xgateway|xpath|xdate|xinfo|xhelp|xmode|xmode_reader|xmode_stream|xmode_thread|xmode_reference|xmode_version|xmode_index|xmode_name|xmode_active|xmode_gateway|xmode_path|xmode_date|xmode_info|xmode_help))\s*\(#i',
            'smtp_port_config' => '#(smtp_port|smtp_host|smtp_user|smtp_pass|smtp_auth|smtp_secure|smtp_from|smtp_to|smtp_timeout|smtp_debug|smtp_keepalive|smtp_pipelining|smtp_verp|smtp_xclient)\s*=\s*#i',
            'mail_server_config' => '#(mail_server|mail_host|mail_port|mail_user|mail_pass|mail_auth|mail_secure|mail_from|mail_to|mail_timeout|mail_debug|mail_transport|mail_protocol|mail_encryption|mail_charset|mail_encoding|mail_content_type|mail_boundary|mail_mime|mail_multipart)\s*=\s*#i',
            'send_email_generic' => '#(function\s+sendEmail|function\s+sendMail|function\s+send_message|function\s+send_notification|function\s+send_newsletter|function\s+mail_send|function\s+email_send|function\s+notify_user|function\s+notify_admin|function\s+trigger_email|function\s+queue_email|function\s+schedule_email|function\s+deliver_email|function\s+transmit_email|function\s+relay_email|function\s+forward_email|function\s+bounce_email|function\s+autoreply|function\s+drip_email|function\s+sequence_email|function\s+campaign_email|function\s+broadcast_email|function\s+blast_email|function\s+newsletter_send|function\s+mass_mail|function\s+bulk_mail|function\s+batch_mail)\s*\(#i',
            'mail_to_url' => '#mailto:\s*#i',
            'wp_mail_smtp' => '#(wp_mail_smtp|WP_Mail_SMTP|easy_wp_smtp|post_smtp|gmail_smtp|outlook_smtp|yahoo_smtp|fluent_smtp|smtp_com)\b#i',
            'email_queue' => '#(email_queue|mail_queue|enqueue_email|enqueue_mail|queue_email|queue_mail|scheduled_email|scheduled_mail|pending_email|pending_mail|outbox|sentbox|drafts)\b#i',
            'socket_class' => '#(class\s+\w+.*Socket|class\s+\w+.*Stream|class\s+\w+.*Connection|class\s+\w+.*Network|class\s+\w+.*Transport)\s*\{#i',
            'socket_method' => '#(function\s+(connect|disconnect|send|receive|readSocket|writeSocket|openSocket|closeSocket|createSocket|bindSocket|listenSocket|acceptSocket|getSocket|setSocket|socketRead|socketWrite|streamRead|streamWrite|pipeOpen|pipeClose|tunnelConnect|proxyConnect|sslConnect|tlsConnect|tcpConnect|udpConnect|rawConnect|networkConnect|transportSend|transportReceive))\s*\(#i',
            'socket_property' => '#(public|protected|private)\s+\$\w*(socket|stream|pipe|connection|transport|network|tcp|udp|ssl|tls)\w*\s*[=;]#i',
            'socket_new' => '#new\s+(Socket|Stream|Connection|Network|Transport|TCP|UDP|SSL|TLS|Pipe|Tunnel|Proxy)\s*\(#i',
            'socket_static' => '#(Socket|Stream|Connection|Network|Transport)::(create|open|connect|send|receive|read|write|listen|accept|bind|close|get|set|configure|init)\s*\(#i',
            'socket_trait' => '#trait\s+\w+.*(Socket|Stream|Connection|Network|Transport)\s*\{#i',
            'socket_interface' => '#interface\s+\w+.*(Socket|Stream|Connection|Network|Transport)\s*\{#i',
            'socket_namespace' => '#namespace\s+.*(Socket|Stream|Connection|Network|Transport|TCP|UDP|SSL|TLS|Pipe|Tunnel|Proxy|Mail|Email|SMTP|IMAP|POP3|NNTP);#i',
            'socket_use' => '#use\s+(.*Socket|.*Stream|.*Connection|.*Network|.*Transport|.*TCP|.*UDP|.*Mail|.*Email|.*SMTP|.*IMAP|.*POP3|Guzzle|Requests|Symfony\\\\Component\\\\Mailer|Illuminate\\\\Mail|Swift_Mailer|PHPMailer|Zend\\\\Mail|Net\\\\SMTP|PEAR\\\\Mail|Horde\\\\Mail|Mailgun|SendGrid|Postmark|SparkPost|Mandrill|Mailjet|Amazon\\\\SES);#i',
            'socket_call_user_func' => '#call_user_func(_array)?\s*\(.*["\'](socket_|stream_|fsockopen|pfsockopen|stream_socket_|proc_open|popen|dns_get_record|dns_check_record|gethostbyname|gethostbyaddr|getmxrr|mail\s*\(|wp_mail|phpmailer|swift_mailer|sendgrid|mailgun|postmark)\b#i',
            'socket_variable_func' => '#\$\w+\s*=\s*["\'](socket_|stream_|fsockopen|pfsockopen|stream_socket_|proc_open|popen|dns_get_record|gethostbyname|getmxrr|mail\s*\(|wp_mail)\b#i',
            'socket_abstract' => '#abstract\s+class\s+\w+.*(Socket|Stream|Connection|Network|Transport)\s*\{#i',
            'socket_extends' => '#extends\s+\w*(Socket|Stream|Connection|Network|Transport|TCP|UDP|SSL|TLS|Pipe|Tunnel|Proxy|Mailer|Email|SMTP|IMAP|POP3)\b#i',
            'socket_implements' => '#implements\s+.*(Socket|Stream|Connection|Network|Transport|Mail|Email|SMTP|IMAP|POP3)\b#i',
            'socket_callback' => '#(add_action|add_filter)\s*\(.*["\'](socket|stream|connection|network|transport|mail|email|smtp|imap|pop3)\b#i',
            'socket_do_action' => '#do_action\s*\(.*["\'](socket|stream|connection|network|transport|mail|email|smtp|imap|pop3)\b#i',
            'socket_apply_filters' => '#apply_filters\s*\(.*["\'](socket|stream|connection|network|transport|mail|email|smtp|imap|pop3)\b#i',
            'socket_hook' => '#(\$this->|self::|static::|parent::)(connect|disconnect|send|receive|read|write|open|close|create|bind|listen|accept|get|set|configure|init|transmit|relay|forward|bounce|deliver|notify|alert|remind|announce|broadcast|campaign|sequence|drip|autoreply|queue|schedule|enqueue|dequeue)\s*\(#i',
            'socket_phpdoc' => '#@(?:param|return|var|property|method)\s+.*(Socket|Stream|Connection|Network|Transport|TCP|UDP|SSL|TLS|Pipe|Tunnel|Proxy|Mail|Email|SMTP|IMAP|POP3|NNTP|Mailer|Message|Notification|Newsletter)\b#i',
            'socket_comment' => '#//\s*(socket|stream|connection|network|transport|tcp|udp|ssl|tls|pipe|mail|email|smtp|imap|pop3|send|receive)\b#i',
            'socket_constant' => '#define\s*\(.*["\'](SOCKET_|STREAM_|SOCK_|TCP_|UDP_|SSL_|TLS_|MAIL_|SMTP_|IMAP_|POP3_|NNTP_)\b#i',
            'socket_ini' => '#ini_(get|set|restore)\s*\(.*["\'](default_socket_timeout|smtp|sendmail_from|sendmail_path|mail|openssl)\b#i',
            'socket_error_handler' => '#set_error_handler|set_exception_handler|restore_error_handler|restore_exception_handler#i',
            'socket_try_catch' => '#try\s*\{[^}]*(?:socket|stream|fsockopen|connection|network|transport|mail|email|smtp|imap|pop3)\b#i',
            'socket_require' => '#(require|require_once|include|include_once)\s*\(?["\'].*(?:socket|stream|connection|network|transport|mail|email|smtp|imap|pop3|mailer|phpmailer|swift|guzzle|requests)\b#i',
            'socket_composer' => '#"(guzzle|requests|symfony/mailer|illuminate/mail|swiftmailer|phpmailer|zend-mail|pear-mail|horde/mail|mailgun|sendgrid|postmark|sparkpost|mandrill|mailjet|aws-sdk|amazon-ses|nette/mail|cakephp/email|yii/mail|codeigniter/email|kohana/email|fuel/email|slim/email|laminas/mail|mezzio/mail)"#i',
        ];

        foreach ($files as $fp) {
            if (microtime(true) - $start_time > 15) break;
            try {
                $ext = strtolower(pathinfo($fp, PATHINFO_EXTENSION));
                if ($ext === 'php') {
                    $size = @filesize($fp);
                    if ($size === false || $size > 524288) continue;
                    $c = @file_get_contents($fp);
                } else {
                    continue;
                }
            } catch (\Throwable $e) { continue; }
            if ($c === false) continue;

            foreach ($curl_patterns as $name => $pat) {
                if (@preg_match($pat, $c)) {
                    if (!in_array($name, $curl_methods, true)) $curl_methods[] = $name;
                    $direct_curl = ['curl_init','curl_setopt','curl_exec','curl_close','curl_version','curl_getinfo','curl_error','curl_reset','curl_copy','curl_pause','curl_upkeep','curl_escape','curl_unescape','curl_strerror','ns_curl'];
                    $indirect_curl = ['var_curl','var_func_curl','cuf_curl','variable_function_call','variable_curl_string','call_user_func_curl','func_get_arg_curl','array_map_curl','array_walk_curl','array_filter_curl','usort_curl','uasort_curl','uksort_curl','array_reduce_curl','preg_replace_callback_curl','register_shutdown_curl','spl_autoload_curl','set_error_handler_curl','set_exception_handler_curl','ob_start_curl','header_register_callback_curl','fastcgi_finish_curl','ignore_user_abort_curl'];
                    if (in_array($name, $direct_curl, true)) $result['has_curl'] = true;
                    if (in_array($name, $indirect_curl, true)) $result['has_curl_indirect'] = true;
                    if ($name === 'curl_multi') $result['has_curl_multi'] = true;
                    if ($name === 'curl_share') $result['has_curl_share'] = true;
                    if (in_array($name, ['http_class','http_method'], true)) $result['has_curl_class'] = true;
                    if ($name === 'ns_curl') $result['has_curl_namespace'] = true;
                    if (in_array($name, ['guzzle','requests_lib','wp_http_curl','http_client'], true)) {
                        $http_libraries[] = $name;
                        if ($name === 'guzzle') $result['has_guzzle'] = true;
                        if ($name === 'requests_lib') $result['has_requests_lib'] = true;
                        if ($name === 'http_client') $result['has_http_client'] = true;
                        if ($name === 'wp_http_curl') $result['has_wp_http'] = true;
                    }
                    if (in_array($name, ['wp_remote','wp_http_api','rest_api'], true)) $result['has_wp_http_api'] = true;
                    if (in_array($name, ['woocommerce_api','stripe_sdk','paypal_sdk','mailchimp_api','elementor_api','gravity_webhook','cf7_recaptcha','rankmath_api','yoast_api'], true)) $result['has_rest_api'] = true;
                    if (in_array($name, ['fsockopen','pfsockopen','stream_socket','socket_create'], true)) $result['has_fsockopen'] = true;
                    if ($name === 'stream_socket') $result['has_stream_socket'] = true;
                    if ($name === 'socket_create') $result['has_socket_raw'] = true;
                    if (in_array($name, ['phpmailer','swiftmailer'], true)) $result['has_phpmailer'] = true;
                    if (in_array($name, ['sendgrid','mailgun','postmark','amazon_ses','symfony_mailer','laravel_mailer','sparkpost','mandrill','mailjet','net_smtp','pear_mail'], true)) $result['has_mail_extended'] = true;
                    if ($name === 'swiftmailer') $result['has_swiftmailer'] = true;
                    if ($name === 'wp_mail') $result['has_wp_mail'] = true;
                    if ($name === 'php_mail') $result['has_php_mail'] = true;
                    if ($name === 'smtp_class') $result['has_smtp_class'] = true;
                    if (in_array($name, ['soap'], true)) $result['has_soap'] = true;
                    if (in_array($name, ['ftp'], true)) $result['has_ftp'] = true;
                    if (in_array($name, ['xmlrpc'], true)) $result['has_xmlrpc'] = true;
                    if (in_array($name, ['curl_file_create'], true)) $result['has_curl_file'] = true;
                    if (in_array($name, ['curl_easy_init','curl_easy_setopt','curl_easy_exec','curl_easy_cleanup','curl_easy_getinfo','curl_easy_strerror','curl_easy_reset','curl_easy_duphandle'], true)) $result['has_curl_easy'] = true;
                    if (in_array($name, ['curl_mime_init','curl_mime_addpart','curl_mime_filedata','curl_mime_name','curl_mime_data'], true)) $result['has_curl_mime'] = true;
                    if (in_array($name, ['curl_formadd','curl_pushfunction'], true)) $result['has_curl_form'] = true;
                    if (in_array($name, ['curl_any','curlopt_any'], true)) $result['has_curl_any'] = true;
                    if (in_array($name, ['curlopt_any'], true)) $result['has_curlopt'] = true;
                    if (in_array($name, ['stream_socket_extended','stream_extended','stream_context'], true)) $result['has_stream_extended'] = true;
                    if (in_array($name, ['socket_extended'], true)) $result['has_socket_extended'] = true;
                    if (in_array($name, ['dns_lookup'], true)) $result['has_dns_lookup'] = true;
                    if (in_array($name, ['socket_any'], true)) $result['has_socket_any'] = true;
                    if (in_array($name, ['socket_class','socket_method','socket_property','socket_new','socket_static','socket_trait','socket_interface','socket_namespace','socket_use','socket_call_user_func','socket_variable_func','socket_abstract','socket_extends','socket_implements','socket_callback','socket_do_action','socket_apply_filters','socket_hook','socket_phpdoc','socket_comment','socket_constant','socket_ini','socket_error_handler','socket_try_catch','socket_require','socket_composer'], true)) $result['has_socket_class'] = true;
                    if (in_array($name, ['stream_any'], true)) $result['has_stream_any'] = true;
                    if (in_array($name, ['mb_send_mail','imap_mail','mail_filter','mail_exec','zend_mail','mail_mime'], true)) $result['has_mail_extended'] = true;
                    if (in_array($name, ['mail_any'], true)) $result['has_mail_any'] = true;
                    if (in_array($name, ['mailparse','ezmlm_hash'], true)) $result['has_mail_extended'] = true;
                    if (in_array($name, ['email_class','notification_send','message_send'], true)) $result['has_email_class'] = true;
                    if (in_array($name, ['imap_open','pop3_class','nntp_class'], true)) $result['has_mail_extended'] = true;
                    if (in_array($name, ['smtp_port_config','mail_server_config'], true)) $result['has_smtp_class'] = true;
                    if (in_array($name, ['send_email_generic','mail_to_url'], true)) $result['has_mail_any'] = true;
                    if (in_array($name, ['wp_mail_smtp'], true)) $result['has_mail_extended'] = true;
                    if (in_array($name, ['email_queue'], true)) $result['has_mail_extended'] = true;
                    if (in_array($name, ['wp_http_any','wp_safe_remote_any'], true)) $result['has_wp_http_any'] = true;
                    if (in_array($name, ['file_get_contents_any','fgc_url'], true)) $result['has_file_get_contents'] = true;
                    if (in_array($name, ['fopen_any','fopen_url'], true)) $result['has_fopen_any'] = true;
                    if (in_array($name, ['copy_any','get_headers','parse_url_http'], true)) $result['has_copy_any'] = true;
                    if (in_array($name, ['readfile_any','readfile_url'], true)) $result['has_readfile_any'] = true;
                    if (in_array($name, ['file_any','file_put_contents_any','fpassthru_any','stream_get_contents_any','stream_copy_any'], true)) $result['has_file_any'] = true;
                    if (in_array($name, ['wp_http_obj'], true)) $result['has_wp_http_obj'] = true;
                    if (in_array($name, ['requests_obj'], true)) $result['has_requests_obj'] = true;
                    if (in_array($name, ['symfony_http'], true)) $result['has_symfony_http'] = true;
                    if (in_array($name, ['laravel_http'], true)) $result['has_laravel_http'] = true;
                    if (in_array($name, ['react_http'], true)) $result['has_react_http'] = true;
                    if (in_array($name, ['amp_http'], true)) $result['has_amp_http'] = true;
                }
            }

            foreach ($obs_pats as $oname => $opat) {
                if (@preg_match($opat, $c)) $obs_found[] = $oname;
            }

            $file_domains = $this->extract_all_domains($c);
            foreach ($file_domains as $d) {
                if (!in_array($d, $domains, true)) $domains[] = $d;
            }
        }

        $result['domains'] = $domains;
        $result['curl_methods'] = $curl_methods;
        $result['http_libraries'] = $http_libraries;

        if (!empty($obs_found)) {
            $result['has_obfuscated'] = true;
            $result['obs_patterns'] = array_values(array_unique($obs_found));
            $result['obs_score'] = min(count($result['obs_patterns']) * 6, 78);
        }

        $score = 0;
        if ($result['has_curl']) $score += 3;
        if ($result['has_curl_multi']) $score += 2;
        if ($result['has_curl_indirect']) $score += 2;
        if ($result['has_curl_class']) $score += 2;
        if ($result['has_fsockopen']) $score += 2;
        if ($result['has_stream_socket']) $score += 2;
        if ($result['has_socket_raw']) $score += 2;
        if (!empty($result['http_libraries'])) $score += 2;
        if ($result['has_wp_http_api']) $score += 1;
        if ($result['has_rest_api']) $score += 1;
        if ($result['has_phpmailer'] || $result['has_swiftmailer']) $score += 1;
        if ($result['has_wp_mail'] || $result['has_php_mail']) $score += 1;
        if ($result['has_smtp_class']) $score += 1;
        if ($result['has_obfuscated']) $score += 1;

        if ($score >= 8) $result['detection_confidence'] = 'high';
        elseif ($score >= 4) $result['detection_confidence'] = 'medium';
        else $result['detection_confidence'] = 'low';

        $this->update_cache($ck, ['time' => time(), 'version' => self::SCAN_VERSION, 'data' => $result]);
        return $result;
    }

    private function get_extension_path($folder) {
        return self::get_extension_path_static($folder);
    }

    private function get_all_files($dir, $limit = 50) {
        return self::get_all_files_static($dir, $limit);
    }

    public function rewrite_extension($folder, $types = ['curl','sock','mail']) {
        if ($this->is_protected_folder($folder)) {
            return ['success' => false, 'message' => 'Protected extension cannot be rewritten.', 'rewritten' => 0];
        }

        $path = $this->get_extension_path($folder);
        if (!$path && $folder !== 'wordpress-core' && $folder !== 'wp-core' && $folder !== 'core') {
            return ['success' => false, 'message' => 'Extension not found.'];
        }

        // Use option-based blocking instead of file modification.
        // Note: won2_rewritten_plugins is managed by AJAX handlers as nested array.
        // This method only updates the runtime blocking lists.
        $key = strtolower($folder);

        $blocked_plugins = (array) get_option('won2_blocked_plugins', []);
        if (!in_array($key, $blocked_plugins, true)) {
            $blocked_plugins[] = $key;
            update_option('won2_blocked_plugins', $blocked_plugins, 'yes');
        }

        return ['success' => true, 'rewritten' => 1, 'skipped' => 0, 'not_writable' => 0, 'errors' => []];
    }

    public function restore_extension($folder, $keep_types = []) {
        $key = strtolower($folder);

        // Note: won2_rewritten_plugins is managed by AJAX handlers as nested array.
        // This method only updates the runtime blocking lists.
        $blocked_plugins = (array) get_option('won2_blocked_plugins', []);
        $blocked_plugins = array_values(array_diff($blocked_plugins, [$key]));
        update_option('won2_blocked_plugins', $blocked_plugins, 'yes');

        if (!empty($keep_types)) {
            $this->rewrite_extension($folder, $keep_types);
        }

        return ['success' => true, 'restored' => 1];
    }

    public function process_next_batch($batch_size = 10) {
        $this->last_processed_count = 0;
        return $this->last_processed_count;
    }

    public function get_last_processed_count() {
        return $this->last_processed_count;
    }
}
}