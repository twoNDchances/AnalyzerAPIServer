from elasticsearch import Elasticsearch
from gather import ES_HOST, ES_USER, ES_PASS, ES_MAX_RESULT


response_elasticsearch = Elasticsearch(hosts=ES_HOST, basic_auth=(ES_USER, ES_PASS))

def load_rule_library():
    if response_elasticsearch.ping() is False:
        print('[Error] Fail to connect to Elasticsearch')
        return False
    else:
        index_settings = {
            "settings": {
                "index": {
                    "max_result_window": ES_MAX_RESULT
                }
            }
        }
        if response_elasticsearch.indices.exists(index='analyzer-actions'):
            response_elasticsearch.indices.delete(index='analyzer-actions')
        
        if response_elasticsearch.indices.exists(index='analyzer-action-timestamps'):
            response_elasticsearch.indices.delete(index='analyzer-action-timestamps')

        if response_elasticsearch.indices.exists(index='analyzer-results'):
            response_elasticsearch.indices.delete(index='analyzer-results')

        if response_elasticsearch.indices.exists(index='analyzer-sqlis'):
            response_elasticsearch.indices.delete(index='analyzer-sqlis')

        if response_elasticsearch.indices.exists(index='analyzer-xsss'):
            response_elasticsearch.indices.delete(index='analyzer-xsss')

        if response_elasticsearch.indices.exists(index='analyzer-fus'):
            response_elasticsearch.indices.delete(index='analyzer-fus')

        if response_elasticsearch.indices.exists(index='analyzer-rules'):
            response_elasticsearch.indices.delete(index='analyzer-rules')

        if response_elasticsearch.indices.exists(index='analyzer-yaras'):
            response_elasticsearch.indices.delete(index='analyzer-yaras')

        response_elasticsearch.indices.create(index="analyzer-actions", body=index_settings)
        response_elasticsearch.indices.create(index="analyzer-action-timestamps", body=index_settings)
        response_elasticsearch.indices.create(index="analyzer-results", body=index_settings)
        response_elasticsearch.indices.create(index="analyzer-sqlis", body=index_settings)
        response_elasticsearch.indices.create(index="analyzer-xsss", body=index_settings)
        response_elasticsearch.indices.create(index="analyzer-fus", body=index_settings)
        response_elasticsearch.indices.create(index="analyzer-rules", body=index_settings)
        response_elasticsearch.indices.create(index="analyzer-yaras", body=index_settings)
        response_elasticsearch.index(index='analyzer-yaras', document={
            'yara_rule': 'rule Detect_PHP_Webshell { meta: author = "Analyzer" description = "Detect PHP webshell" version = "1.0" date = "2024-11-18" reference = "Custom Rule for detecting malicious PHP scripts" strings: $php_start = "<?php" $eval = "eval(" $base64_decode = "base64_decode(" $exec = "exec(" $system = "system(" $shell_exec = "shell_exec(" $passthru = "passthru(" $cmd_pattern = /cmd=[a-zA-Z0-9_\\-]+/ $suspicious_code = /[A-Za-z0-9+\\/=]{50,}/ condition: any of them }',
            'yara_description': 'Detect PHP webshell',
            'yara_rule_original': 
'''
rule Detect_PHP_Webshell
{
    meta:
        author = "Analyzer"
        description = "Detect PHP webshell"
        version = "1.0"
        date = "2024-11-18"
        reference = "Custom Rule for detecting malicious PHP scripts"
    
    strings:
        $php_start = "<?php"
        $eval = "eval("
        $base64_decode = "base64_decode("
        $exec = "exec("
        $system = "system("
        $shell_exec = "shell_exec("
        $passthru = "passthru("
        $cmd_pattern = /cmd=[a-zA-Z0-9_\\-]+/
        $suspicious_code = /[A-Za-z0-9+\\/=]{50,}/

    condition:
        any of them
}
''',
            'yara_description_original': 'Detect PHP webshell'
        })
        response_elasticsearch.index(index='analyzer-yaras', document={
            'yara_rule': 'rule php_anuna { meta: author = "Vlad https://github.com/vlad-s" date = "2016/07/18" description = "Catches a PHP Trojan" strings: $a = /<\\?php \\$[a-z]+ = \'/ $b = /\\$[a-z]+=explode\\(chr\\(\\([0-9]+[-+][0-9]+\\)\\)/ $c = /\\$[a-z]+=\\([0-9]+[-+][0-9]+\\)/ $d = /if \\(!function_exists\\(\'[a-z]+\'\\)\\)/ condition: all of them }',
            'yara_description': 'Detect PHP webshell',
            'yara_rule_original':
'''
rule php_anuna
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Catches a PHP Trojan"
    strings:
        $a = /<\\?php \\$[a-z]+ = '/
        $b = /\\$[a-z]+=explode\\(chr\\(\\([0-9]+[-+][0-9]+\\)\\)/
        $c = /\\$[a-z]+=\\([0-9]+[-+][0-9]+\\)/
        $d = /if \\(!function_exists\\('[a-z]+'\\)\\)/
    condition:
        all of them
}
''',
            'yara_description_original': 'Detect PHP webshell'
        })
        response_elasticsearch.index(index='analyzer-yaras', document={
            'yara_rule': 'rule php_in_image { meta: author = "Vlad https://github.com/vlad-s" date = "2016/07/18" description = "Finds image files w/ PHP code in images" strings: $gif = /^GIF8[79]a/ $jfif = { ff d8 ff e? 00 10 4a 46 49 46 } $png = { 89 50 4e 47 0d 0a 1a 0a } $php_tag = "<?php" condition: (($gif at 0) or ($jfif at 0) or ($png at 0)) and $php_tag }',
            'yara_description': 'Detect PHP webshell',
            'yara_rule_original':
'''
rule php_in_image
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Finds image files w/ PHP code in images"
    strings:
        $gif = /^GIF8[79]a/
        $jfif = { ff d8 ff e? 00 10 4a 46 49 46 }
        $png = { 89 50 4e 47 0d 0a 1a 0a }
        $php_tag = "<?php"
    condition:
        (($gif at 0) or
        ($jfif at 0) or
        ($png at 0)) and
        $php_tag
}
''',
            'yara_description_original': 'Detect PHP webshell'
        })
        sqli_rules = [
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|UNION|GRANT|REVOKE|SHOW)\\b',
                'rule_description': 'Common SQL keywords'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\b(OR|AND)\\s+\\d+=\\d+',
                'rule_description': 'Boolean logic statements'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|UNION|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|IN|SLEEP|BENCHMARK|WAITFOR)\\b)',
                'rule_description': 'Common statement for MySQL'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|UNION|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|IN|SLEEP|BENCHMARK|WAITFOR)\\b)',
                'rule_description': 'Common statement for PostgreSQL'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|UNION|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|IN|SLEEP|DBMS_LOCK.SLEEP)\\b)',
                'rule_description': 'Common statement for Oracle'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|UNION|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|IN|WAITFOR)\\b)',
                'rule_description': 'Common statement for SQL Server'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\b(UNION SELECT|INFORMATION_SCHEMA|TABLE_NAME|COLUMN_NAME|LOAD_FILE|INTO OUTFILE|INTO DUMPFILE)\\b',
                'rule_description': 'Advanced SQLi techniques'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\'\\s*=\\s*\'|"\\s*=\\s*"',
                'rule_description': 'Direct comparison of strings (Example: \'admin\' = \'admin\')'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '([\'"]?;\\s*--\\s*)',
                'rule_description': 'Common payload'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\b(ADD COLUMN|ALTER COLUMN|DROP COLUMN|RENAME COLUMN|RENAME TABLE|REPLACE INTO|INTO OUTFILE|INTO DUMPFILE|CASE WHEN)\\b',
                'rule_description': 'Database and table manipulation commands'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\b(VERSION|DATABASE|USER|SYSTEM_USER|SESSION_USER|CURRENT_USER|BENCHMARK|SLEEP|RAND|MD5|SHA1|SHA2)\\b',
                'rule_description': 'Suspicious function calls (Example: version, database)'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '0x[0-9A-Fa-f]+',
                'rule_description': 'Hexadecimal values (often used in injections)'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '\\|\\|',
                'rule_description': 'Concatenation with || operator (specific to certain SQL dialects)'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\b\\d+\\s*=\\s*\\d+\\b',
                'rule_description': 'Detect conditions with tautologies (Example: \'1\'=\'1\')'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\b(.+\\s*R?LIKE\\s*([\'"].*[\'"]|\\((\\w*|.*)\\))|.*(\\s*[\'"]|\\s+\\d+)\\s*R?LIKE\\s+\\d+\\s*)\\b',
                'rule_description': 'Detect using LIKE condition'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\b(EXEC\\s*\\(\\s*(@\\w+|[\'"].*[\'"])\\s*\\);|EXEC?\\s+\\w+\\s+@\\w+\\s*=\\s*|EXECUTE\\s+\\w+\\s*;|EXECUTE\\s*(\\w+|[\'"].*[\'"]);)\\b',
                'rule_description': 'Detect using EXEC (or EXECUTE) statment'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\b(INTO?\\s*OUTFILE\\s*[\'"].*[\'"]|COPY\\s*(\\w+|[\'"].*[\'"]|\\(.*\\))\\s*(TO|FROM)\\s+PROGRAM)\\b',
                'rule_description': 'Detect using SQLi to RCE'
            }
        ]

        xss_rules = [
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)<.*?(=|:|>)(.*?[\"\']|>|.*?)>',
                'rule_description': 'Detect html injection'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)<.*?script.*?>.*?(</script>)?',
                'rule_description': 'Detect <script> tags'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)<.*?img.*?\\b[^>]*?(onerror.*?=|>)',
                'rule_description': 'Detect img onerror event'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)<.*?iframe.*?>(.*?)?(</.*?iframe.*?>)?',
                'rule_description': 'Detect iframe tags'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)<.*?body.*?\\b[^>]*?(onload.*?=|>)',
                'rule_description': 'Detect body onload event'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)<.*?svg.*?(=|>)(</svg>)?',
                'rule_description': 'Detect svg with events'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)<.*?div.*?style=.*?expression\\(.*?\\).*?>',
                'rule_description': 'Detect CSS expression in style'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)<.*?input.*?type=.*?hidden.*?value=.*?javascript:.*?>',
                'rule_description': 'Detect hidden input with javascript'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)(\\"|\'|)\\s*alert\\(.*?\\);?(\\\\"|\'|)',
                'rule_description': 'Detect alert() usage'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)<.*?form.*?action=.*?javascript:.*?>',
                'rule_description': 'Detect form with javascript action'
            },
        ]

        fu_rules = [
            {
                'rule_type': 'FU',
                'rule_execution': '\\b(exec|eval|passthru|shell_exec|system|popen|proc_open)\\b',
                'rule_description': 'System exec'
            },
            {
                'rule_type': 'FU',
                'rule_execution': '\\b(file_get_contents|fopen|readfile|include|require|include_once|require_once)\\b',
                'rule_description': 'File operations'
            },
            {
                'rule_type': 'FU',
                'rule_execution': '\\b(base64_decode|base64_encode|gzinflate|gzdecode|gzuncompress)\\b',
                'rule_description': 'Encoding'
            },
            {
                'rule_type': 'FU',
                'rule_execution': '\\$\\{?\\$_(GET|POST|REQUEST|COOKIE|SERVER)\\b',
                'rule_description': 'Variable access'
            },
            {
                'rule_type': 'FU',
                'rule_execution': '\b(chmod|unlink|curl_exec|curl_multi_exec|apache_child_terminate|posix_kill|posix_mkfifo|posix_setsid|proc_get_status|proc_nice)\\b',
                'rule_description': 'Dangerous functions'
            },
        ]

        for sqli_rule in sqli_rules:
            response_elasticsearch.index(index="analyzer-rules", document=sqli_rule)

        for xss_rule in xss_rules:
            response_elasticsearch.index(index="analyzer-rules", document=xss_rule)

        for fu_rule in fu_rules:
            response_elasticsearch.index(index="analyzer-rules", document=fu_rule)
    return True
 