from elasticsearch import Elasticsearch
from json import dumps
from gather import ES_HOST, ES_USER, ES_PASS, ES_MAX_RESULT, BACKEND_DEFAULT_WEBHOOK
from time import sleep


es = Elasticsearch(hosts=ES_HOST, basic_auth=(ES_USER, ES_PASS))

def check_elasticsearch():
    while True:
        try:
            if es.ping() is True:
                break
            else:
                print('[Warning] Ping for test connection fail, will try again after 5 seconds...')
                sleep(5)
        except:
            print('[Warning] Ping for test connection fail, will try again after 5 seconds...') 
            sleep(5)
            continue
    index_settings = {
        "settings": {
            "index": {
                "max_result_window": int(ES_MAX_RESULT)
            }
        }
    }
    print('[Info] Perform check "analyzer-actions" index...')
    action_id = None
    if not es.indices.exists(index='analyzer-actions'):
        print('[Info] Creating "analyzer-actions"...')
        es.indices.create(index="analyzer-actions", body=index_settings)
        print('[Info] Created "analyzer-actions"')
        print('[Info] Preparing to create default action...')
        action_id = es.index(index='analyzer-actions', document={
            'action_name': 'default-action-responser',
            'action_type': 'webhook',
            'action_configuration': dumps({
                'url': BACKEND_DEFAULT_WEBHOOK,
                'type': 'custom',
                'body': {
                    'message': '$result'
                },
                'method': 'POST',
                'connection_timeout': 2,
                'data_read_timeout': 6,
                'advanced': {
                    'is_enabled': True,
                    'threshold': 3,
                    'time_window_seconds': 30
                }
            })
        })
        while True:
            default_action = es.search(index='analyzer-actions', query={
                'term': {
                    'action_name.keyword': 'default-action-responser'
                }
            }, size=ES_MAX_RESULT).raw
            if default_action['hits']['hits'].__len__() > 0:
                break
        print('[Info] Created all default action')
    print('[Info] Check done')
    print('[Info] Perform check "analyzer-action-timestamps" index...')
    if not es.indices.exists(index='analyzer-action-timestamps'):
        print('[Info] Creating "analyzer-action-timestamps"...')
        es.indices.create(index="analyzer-action-timestamps", body=index_settings)
        print('[Info] Created "analyzer-action-timestamp"')
    print('[Info] Check done')
    print('[Info] Perform check "analyzer-results" index...')
    if not es.indices.exists(index='analyzer-results'):
        print('[Info] Creating "analyzer-results"...')
        es.indices.create(index="analyzer-results", body=index_settings)
        print('[Info] Created "analyzer-results"')
    print('[Info] Check done')
    print('[Info] Perform check "analyzer-errorlogs" index...')
    if not es.indices.exists(index='analyzer-errorlogs'):
        print('[Info] Creating "analyzer-errorlogs"...')
        es.indices.create(index='analyzer-errorlogs', body=index_settings)
        print('[Info] Created "analyzer-errorlogs"')
    print('[Info] Check done')
    print('[Info] Perform check "analyzer-sqlis" index...')
    action_id = es.search(index='analyzer-actions', query={
        'term': {
            'action_name.keyword': 'default-action-responser'
        }
    }, size=ES_MAX_RESULT).raw['hits']['hits']
    if action_id.__len__() == 0:
        action_id = es.index(index='analyzer-actions', document={
            'action_name': 'default-action-responser',
            'action_type': 'webhook',
            'action_configuration': dumps({
                'url': BACKEND_DEFAULT_WEBHOOK,
                'type': 'custom',
                'body': {
                    'message': '$result'
                },
                'method': 'POST',
                'connection_timeout': 2,
                'data_read_timeout': 6,
                'advanced': {
                    'is_enabled': True,
                    'threshold': 3,
                    'time_window_seconds': 30
                }
            })
        })
    else:
        action_id = action_id[0]
    if not es.indices.exists(index='analyzer-sqlis'):
        print('[Info] Creating "analyzer-sqlis"...')
        es.indices.create(index="analyzer-sqlis", body=index_settings)
        print('[Info] Created "analyzer-sqlis"')
        es.index(index='analyzer-sqlis', document={
            'rule_name': 'default-sqli-analyzer',
            'is_enabled': True,
            'target_field': 'request_body',
            'ip_root_cause_field': 'ip_address',
            'regex_matcher': '',
            'rule_library': 'SQLI',
            'action_id': action_id['_id'],
            'type_attack': 'sqli',
            'wordlist': None
        })
    print('[Info] Check done')
    print('[Info] Perform check "analyzer-xsss" index...')
    if not es.indices.exists(index='analyzer-xsss'):
        print('[Info] Creating "analyzer-xsss"...')
        es.indices.create(index="analyzer-xsss", body=index_settings)
        print('[Info] Created "analyzer-xsss"')
        es.index(index='analyzer-xsss', document={
            'rule_name': 'default-xss-analyzer',
            'is_enabled': True,
            'target_field': 'request_body',
            'ip_root_cause_field': 'ip_address',
            'regex_matcher': '',
            'rule_library': 'XSS',
            'action_id': action_id['_id'],
            'type_attack': 'xss'
        })
    print('[Info] Check done')
    print('[Info] Perform check "analyzer-fus" index...')
    if not es.indices.exists(index='analyzer-fus'):
        print('[Info] Creating "analyzer-fus"...')
        es.indices.create(index="analyzer-fus", body=index_settings)
        print('[Info] Created "analyzer-fus"')
        es.index(index='analyzer-fus', document={
            'rule_name': 'default-fu-analyzer',
            'is_enabled': True,
            'target_field': 'request_body',
            'ip_root_cause_field': 'ip_address',
            'regex_matcher': '',
            'rule_library': 'FU',
            'yara_rule_intergration': True,
            'action_id': action_id['_id'],
            'type_attack': 'fu'
        })
    print('[Info] Check done')
    print('[Info] Perform check "analyzer-rules" index...')
    if not es.indices.exists(index='analyzer-rules'):
        print('[Info] Creating "analyzer-rules"...')
        es.indices.create(index="analyzer-rules", body=index_settings)
        print('[Info] Created "analyzer-rules"')
        print('[Info] Preparing to create default rule of SQLIs...')
        sqli_rules = [
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\s*EXEC\\s*\\(\\s*(@\\w+|[\'"].*[\'"])\\s*\\);|EXEC?\\s+\\w+\\s+@\\w+\\s*=\\s*|EXECUTE\\s+\\w+\\s*;|EXECUTE\\s*(\\w+|[\'"].*[\'"])\\s*;\\s*',
                'rule_description': 'Detect using EXEC (or EXECUTE) statment'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\s*INTO?\\s*OUTFILE\\s*[\'"].*[\'"]|COPY\\s*(\\w+|[\'"].*[\'"]|\\(.*\\))\\s*(TO|FROM)\\s+PROGRAM\\s*',
                'rule_description': 'Detect using SQLi to RCE'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\s*UNION\\s+SELECT\\s*',
                'rule_description': 'Detect using SQLi by UNION'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i).*pg_(catalog|sleep)',
                'rule_description': 'Detect using SQLi by sleep function'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)["\'`](?:[\\s\\x0b]*![\\s\\x0b]*["\'0-9A-Z_-z]|;?[\\s\\x0b]*(?:having|select|union\\b[\\s\\x0b]*(?:all|(?:distin|sele)ct))\\b[\\s\\x0b]*[^\\s\\x0b])|\\b(?:(?:(?:c(?:onnection_id|urrent_user)|database|schema|user)[\\s\\x0b]*?|select.*?[0-9A-Z_a-z]?user)\\(|exec(?:ute)?[\\s\\x0b]+master\\.|from[^0-9A-Z_a-z]+information_schema[^0-9A-Z_a-z]|into[\\s\\x0b\\+]+(?:dump|out)file[\\s\\x0b]*?["\'`]|union(?:[\\s\\x0b]select[\\s\\x0b]@|[\\s\\x0b\\(0-9A-Z_a-z]*?select))|[\\s\\x0b]*?exec(?:ute)?.*?[^0-9A-Z_a-z]xp_cmdshell|[^0-9A-Z_a-z]iif[\\s\\x0b]*?\\(',
                'rule_description': 'Detect using SQLi by UNION'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|GRANT|REVOKE|SHOW)\\b',
                'rule_description': 'Common SQL keywords'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\b(OR|AND)\\s+\\d+=\\d+',
                'rule_description': 'Boolean logic statements'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|IN|SLEEP|BENCHMARK|WAITFOR)\\b)',
                'rule_description': 'Common statement for MySQL'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|IN|SLEEP|BENCHMARK|WAITFOR)\\b)',
                'rule_description': 'Common statement for PostgreSQL'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|IN|SLEEP|DBMS_LOCK.SLEEP)\\b)',
                'rule_description': 'Common statement for Oracle'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|IN|WAITFOR)\\b)',
                'rule_description': 'Common statement for SQL Server'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i)\\b(INFORMATION_SCHEMA|TABLE_NAME|COLUMN_NAME|LOAD_FILE|INTO OUTFILE|INTO DUMPFILE)\\b',
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
                'rule_execution': '(?i)\\b\\d+=\\d+\\b',
                'rule_description': 'Detect conditions with tautologies (Example: 1 = 1)'
            },
            {
                'rule_type': 'SQLI',
                'rule_execution': '(?i).+\\s*R?LIKE\\s*([\'"].*[\'"]|\\((\\w*|.*)\\))|.*(\\s*[\'"]|\\s+\\d+)\\s*R?LIKE\\s+\\d+\\s*',
                'rule_description': 'Detect using LIKE condition'
            }
        ]
        for sqli_rule in sqli_rules:
            es.index(index="analyzer-rules", document=sqli_rule)
        print('[Info] Created all default rule of SQLis')
        print('[Info] Preparing to create default rule of XSSs...')
        xss_rules = [
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)<.*?(=|:|>)(.*?[\'"]|>|.*?)',
                'rule_description': 'Detect html injection'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)(.*java|<).*script(:|>|.*)',
                'rule_description': 'Detect javascript or script tag injection'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)<.*?img.*?[^>]*?(.*?=|>)',
                'rule_description': 'Detect img tag injection'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)(alert|prompt|confirm).*[\\(\'"]+.*',
                'rule_description': 'Detect danger function injection'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)(?=.*[a-z])(?=.*[0-9a-fA-F])<.*?(=|:|>)(.*?[\'"]|>|.*?)',
                'rule_description': 'Detect all tag injection'
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
                'rule_execution': '(?i)([\'"]|)\\s*alert\\(.*?\\);?([\'"]|)',
                'rule_description': 'Detect alert() usage'
            },
            {
                'rule_type': 'XSS',
                'rule_execution': '(?i)<.*?form.*?action=.*?javascript:.*?>',
                'rule_description': 'Detect form with javascript action'
            },
        ]
        for xss_rule in xss_rules:
            es.index(index="analyzer-rules", document=xss_rule)
        print('[Info] Created all default rule of XSSs')
        print('[Info] Preparing to create default rule of FUs...')
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
        for fu_rule in fu_rules:
            es.index(index="analyzer-rules", document=fu_rule)
        print('[Info] Created all default rule of FUs')
    print('[Info] Check done')
    print('[Info] Perform check "analyzer-yaras" index...')
    if not es.indices.exists(index='analyzer-yaras'):
        print('[Info] Creating "analyzer-yaras"...')
        es.indices.create(index="analyzer-yaras", body=index_settings)
        print('[Info] Created "analyzer-yaras"')
        print('[Info] Preparing to create default rule of YARAs...')
        es.index(index='analyzer-yaras', document={
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
        es.index(index='analyzer-yaras', document={
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
        es.index(index='analyzer-yaras', document={
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
        print('[Info] Created all default rule of YARAs')
    print('[Info] Check done')

    print('[Info] Perform check "analyzer-wordlists" index...')
    if not es.indices.exists(index='analyzer-wordlists'):
        print('[Info] Creating "analyzer-wordlists"...')
        es.indices.create(index="analyzer-wordlists", body=index_settings)
        print('[Info] Created "analyzer-wordlists"')
    print('[Info] Check done')

    es.indices.put_settings(
        index='analyzer-actions',
        body={
            "index": {
                "max_result_window": ES_MAX_RESULT
            }
        }
    )
    es.indices.put_settings(
        index='analyzer-fus',
        body={
            "index": {
                "max_result_window": ES_MAX_RESULT
            }
        }
    )
    es.indices.put_settings(
        index='analyzer-results',
        body={
            "index": {
                "max_result_window": ES_MAX_RESULT
            }
        }
    )
    es.indices.put_settings(
        index='analyzer-rules',
        body={
            "index": {
                "max_result_window": ES_MAX_RESULT
            }
        }
    )
    es.indices.put_settings(
        index='analyzer-sqlis',
        body={
            "index": {
                "max_result_window": ES_MAX_RESULT
            }
        }
    )
    es.indices.put_settings(
        index='analyzer-xsss',
        body={
            "index": {
                "max_result_window": ES_MAX_RESULT
            }
        }
    )
    es.indices.put_settings(
        index='analyzer-yaras',
        body={
            "index": {
                "max_result_window": ES_MAX_RESULT
            }
        }
    )
    es.indices.put_settings(
        index='analyzer-wordlists',
        body={
            "index": {
                "max_result_window": ES_MAX_RESULT
            }
        }
    )
