from elasticsearch import Elasticsearch
from gather import ES_HOST, ES_USER, ES_PASS, ES_MAX_RESULT


es = Elasticsearch(hosts=ES_HOST, basic_auth=(ES_USER, ES_PASS))


if es.ping() is False:
    print('Fail to connect to Elasticsearch')
    
else:
    index_settings = {
        "settings": {
            "index": {
                "max_result_window": ES_MAX_RESULT
            }
        }
    }
    if es.indices.exists(index='analyzer-actions'):
        es.indices.delete(index='analyzer-actions')

    if es.indices.exists(index='analyzer-results'):
        es.indices.delete(index='analyzer-results')

    if es.indices.exists(index='analyzer-sqlis'):
        es.indices.delete(index='analyzer-sqlis')

    if es.indices.exists(index='analyzer-xsss'):
        es.indices.delete(index='analyzer-xsss')
    
    if es.indices.exists(index='analyzer-rules'):
        es.indices.delete(index='analyzer-rules')

    es.indices.create(index="analyzer-actions", body=index_settings)
    es.indices.create(index="analyzer-results", body=index_settings)
    es.indices.create(index="analyzer-sqlis", body=index_settings)
    es.indices.create(index="analyzer-xsss", body=index_settings)
    es.indices.create(index="analyzer-rules", body=index_settings)
    sqli_rules = [
        {
            'rule_type': 'SQLI',
            'rule_execution': '(?i)\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|EXEC|UNION|GRANT|REVOKE|SHOW)\\b',
            'rule_description': 'Common SQL keywords'
        },
        {
            'rule_type': 'SQLI',
            'rule_execution': '(?i)\\b(OR|AND)\\s+\\d+=\\d+',
            'rule_description': 'Boolean logic statements'
        },
        {
            'rule_type': 'SQLI',
            'rule_execution': '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|EXEC|UNION|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|LIKE|IN|SLEEP|BENCHMARK|WAITFOR|EXECUTE)\\b)',
            'rule_description': 'Common statement for MySQL'
        },
        {
            'rule_type': 'SQLI',
            'rule_execution': '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|EXEC|UNION|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|LIKE|IN|SLEEP|BENCHMARK|WAITFOR)\\b)',
            'rule_description': 'Common statement for PostgreSQL'
        },
        {
            'rule_type': 'SQLI',
            'rule_execution': '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|EXEC|UNION|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|LIKE|IN|SLEEP|DBMS_LOCK.SLEEP)\\b)',
            'rule_description': 'Common statement for Oracle'
        },
        {
            'rule_type': 'SQLI',
            'rule_execution': '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|EXEC|UNION|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|LIKE|IN|WAITFOR)\\b)',
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
            'rule_execution': '(?i)<.*?img.*?\b[^>]*?(onerror.*?=|>)',
            'rule_description': 'Detect img onerror event'
        },
        {
            'rule_type': 'XSS',
            'rule_execution': '(?i)<.*?iframe.*?>(.*?)?(</.*?iframe.*?>)?',
            'rule_description': 'Detect iframe tags'
        },
        {
            'rule_type': 'XSS',
            'rule_execution': '(?i)<.*?body.*?\b[^>]*?(onload.*?=|>)',
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

    for sqli_rule in sqli_rules:
        es.index(index="analyzer-rules", document=sqli_rule)

    for xss_rule in xss_rules:
        es.index(index="analyzer-rules", document=xss_rule)

    es.index(index='analyzer-sqlis', document={
        'rule_name': 'my-rule-1',
        'is_enabled': True,
        'target_field': 'request.body',
        'ip_root_cause_field': 'client.ip',
        'regex_matcher': '(?i)\\b(OR|AND)\\s+\\d+=\\d+',
        'rule_library': None,
        'action_id': None,
        'type_attack': 'sqli'
    })
    es.index(index='analyzer-sqlis', document={
        'rule_name': 'my-rule-2',
        'is_enabled': True,
        'target_field': 'request.body',
        'ip_root_cause_field': 'client.ip',
        'regex_matcher': '(?i)\\b(OR|AND)\\s+\\d+=\\d+',
        'rule_library': None,
        'action_id': None,
        'type_attack': 'sqli'
    })
    es.index(index='analyzer-sqlis', document={
        'rule_name': 'my-rule-3',
        'is_enabled': True,
        'target_field': 'request.body',
        'ip_root_cause_field': 'client.ip',
        'regex_matcher': '(?i)\\b(OR|AND)\\s+\\d+=\\d+',
        'rule_library': None,
        'action_id': None,
        'type_attack': 'sqli'
    })
    es.index(index='analyzer-sqlis', document={
        'rule_name': 'my-rule-4',
        'is_enabled': True,
        'target_field': 'request.body',
        'ip_root_cause_field': 'client.ip',
        'regex_matcher': '(?i)\\b(OR|AND)\\s+\\d+=\\d+',
        'rule_library': None,
        'action_id': None,
        'type_attack': 'sqli'
    })
    es.index(index='analyzer-sqlis', document={
        'rule_name': 'my-rule-5',
        'is_enabled': True,
        'target_field': 'request.body',
        'ip_root_cause_field': 'client.ip',
        'regex_matcher': '(?i)\\b(OR|AND)\\s+\\d+=\\d+',
        'rule_library': None,
        'action_id': None,
        'type_attack': 'sqli'
    })
    es.index(index='analyzer-sqlis', document={
        'rule_name': 'my-rule-6',
        'is_enabled': True,
        'target_field': 'request.body',
        'ip_root_cause_field': 'client.ip',
        'regex_matcher': '(?i)\\b(OR|AND)\\s+\\d+=\\d+',
        'rule_library': None,
        'action_id': None,
        'type_attack': 'sqli'
    })
    es.index(index='analyzer-xsss', document={
        'rule_name': 'my-rule-7',
        'is_enabled': True,
        'target_field': 'request.body',
        'ip_root_cause_field': 'client.ip',
        'regex_matcher': '(?i)\\b(OR|AND)\\s+\\d+=\\d+',
        'rule_library': None,
        'action_id': None,
        'type_attack': 'xss'
    })
    es.index(index='analyzer-xsss', document={
        'rule_name': 'my-rule-8',
        'is_enabled': True,
        'target_field': 'request.body',
        'ip_root_cause_field': 'client.ip',
        'regex_matcher': '(?i)<.*?(=|:|>)(.*?[\"\']|>|.*?)>',
        'rule_library': None,
        'action_id': None,
        'type_attack': 'xss'
    })
    es.index(index='analyzer-xsss', document={
        'rule_name': 'my-rule-9',
        'is_enabled': True,
        'target_field': 'request.body',
        'ip_root_cause_field': 'client.ip',
        'regex_matcher': '(?i)<.*?(=|:|>)(.*?[\"\']|>|.*?)>',
        'rule_library': None,
        'action_id': None,
        'type_attack': 'xss'
    })
    es.index(index='analyzer-xsss', document={
        'rule_name': 'my-rule-10',
        'is_enabled': True,
        'target_field': 'request.body',
        'ip_root_cause_field': 'client.ip',
        'regex_matcher': '(?i)<.*?(=|:|>)(.*?[\"\']|>|.*?)>',
        'rule_library': None,
        'action_id': None,
        'type_attack': 'xss'
    })
    es.index(index='analyzer-xsss', document={
        'rule_name': 'my-rule-11',
        'is_enabled': True,
        'target_field': 'request.body',
        'ip_root_cause_field': 'client.ip',
        'regex_matcher': '(?i)<.*?(=|:|>)(.*?[\"\']|>|.*?)>',
        'rule_library': None,
        'action_id': None,
        'type_attack': 'xss'
    })
    es.index(index='analyzer-xsss', document={
        'rule_name': 'my-rule-12',
        'is_enabled': True,
        'target_field': 'request.body',
        'ip_root_cause_field': 'client.ip',
        'regex_matcher': '(?i)<.*?(=|:|>)(.*?[\"\']|>|.*?)>',
        'rule_library': None,
        'action_id': None,
        'type_attack': 'xss'
    })
