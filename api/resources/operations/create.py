from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from flask import request
from flask_restful import Resource
from json import loads
import re
import requests
import yara
import yaml
from ...storage import response_elasticsearch, ES_MAX_RESULT, ES_USER, ES_PASS


class ResourceCreations(Resource):
    def post(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'resources',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        try:
            loads(request.data)
        except:
            return {
                'type': 'resources',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        elasticsearch_username = request_body.get('loadResourceElasticsearchUsername')
        elasticsearch_password = request_body.get('loadResourceElasticsearchPassword')
        resource_definition = request_body.get('resourceDefinition')
        if elasticsearch_username is None or elasticsearch_password is None or resource_definition is None:
            return {
                'type': 'resources',
                'data': None,
                'reason': 'BadRequest: "loadResourceElasticsearchUsername", "loadResourceElasticsearchPassword", "resourceDefinition" are required'
            }, 400
        if elasticsearch_username != ES_USER or elasticsearch_password != ES_PASS:
            return {
                'type': 'storages', 
                'reason': 'Unauthorized: Incorrect Username or Password', 
                'data': None
            }, 401
        try:
            yaml_configuration = dict(yaml.safe_load(request_body.get('resourceDefinition')))
        except:
            return {
                'type': 'resources',
                'data': None,
                'reason': 'BadRequest: Resource Definition must be YAML'
            }, 400
        actions = yaml_configuration.get('actions')
        fus = yaml_configuration.get('fus')
        rules = yaml_configuration.get('rules')
        sqlis = yaml_configuration.get('sqlis')
        xsss = yaml_configuration.get('xsss')
        yaras = yaml_configuration.get('yaras')
        wordlists = yaml_configuration.get('wordlists')
        logs: dict[dict[str, None | dict | str]] = {
            'actions': {
                'datatype': None,
                'fields': [],
                'validations': {
                    'action_name': [],
                    'action_type': [],
                    'action_configuration': []
                },
                'passed': []
            },
            'fus': {
                'datatype': None,
                'fields': [],
                'validations': {
                    'rule_name': [],
                    'is_enabled': [],
                    'target_field': [],
                    'ip_root_cause_field': [],
                    'regex_matcher': [],
                    'rule_library': [],
                    'yara_rule_intergration': [],
                    'action': []
                },
                'passed': []
            },
            'rules': {
                'datatype': None,
                'fields': [],
                'validations': {
                    'rule_type': [],
                    'includes': [],
                    'definitions': []
                },
                'passed': []
            },
            'sqlis': {
                'datatype': None,
                'fields': [],
                'validations': {
                    'rule_name': [],
                    'is_enabled': [],
                    'target_field': [],
                    'ip_root_cause_field': [],
                    'regex_matcher': [],
                    'rule_library': [],
                    'action': []
                },
                'passed': []
            },
            'xsss': {
                'datatype': None,
                'fields': [],
                'validations': {
                    'rule_name': [],
                    'is_enabled': [],
                    'target_field': [],
                    'ip_root_cause_field': [],
                    'regex_matcher': [],
                    'rule_library': [],
                    'action': []
                },
                'passed': []
            },
            'yaras': {
                'datatype': None,
                'fields': [],
                'validations': {
                    'yara_rule': []
                },
                'passed': []
            },
            'wordlists': {
                'datatype': None,
                'fields': [],
                'validations': {
                    'wordlist_name': [],
                    'content': []
                },
                'passed': []
            }
        }
        if actions is not None:
            if not isinstance(actions, list):
                logs['actions']['datatype'] = 'Wrong, must be <list>'
            else:
                for action in actions:
                    action_name = action.get('action_name')
                    action_type = action.get('action_type')
                    action_configuration = self.normalize_string(text=action.get('action_configuration'))
                    if not action_name or not action_type or not action_configuration:
                        logs['actions']['fields'].append(f'Missing "action_name", "action_type", "action_configuration"')
                        continue
                    if not isinstance(action_name, str):
                        logs['actions']['validations']['action_name'].append(f'"action_name" must be a <string>')
                        continue
                    if not isinstance(action_type, str):
                        logs['actions']['validations']['action_type'].append(f'"action_type" must be a <string>')
                        continue
                    if not isinstance(action_configuration, str):
                        logs['actions']['validations']['action_configuration'].append(f'"action_configuration" must be a <string>')
                        continue
                    if sum(1 for d in actions if action_name in d.values()) > 1:
                        logs['actions']['validations']['action_name'].append(f'{action_name} is exist in your YAML file')
                        continue
                    elasticsearch_actions = response_elasticsearch.search(index='analyzer-actions', query={
                        'term': {
                            'action_name.keyword': action_name
                        }
                    }, size=ES_MAX_RESULT)
                    elasticsearch_action_list = elasticsearch_actions.raw['hits']['hits']
                    if elasticsearch_action_list.__len__() > 0:
                        logs['actions']['validations']['action_name'].append(f'{action_name} is exist in Elasticsearch')
                        continue
                    if action_type not in ['webhook', 'email']:
                        logs['actions']['validations']['action_type'].append(f'{action_type} must in ["webhook", "email"]')
                        continue
                    try:
                        action_configuration_json = dict(loads(action_configuration))
                    except:
                        logs['actions']['validations']['action_configuration'].append(f'{action_configuration} must be JSON format')
                        continue
                    advanced = action_configuration_json.get('advanced')
                    if advanced is None:
                        logs['actions']['validations']['action_configuration'].append(f'{action_name} must have "advanced" in "action_configuration"')
                        continue
                    is_enabled = advanced.get('is_enabled')
                    threshold = advanced.get('threshold')
                    time_window_seconds = advanced.get('time_window_seconds')
                    if is_enabled is None or threshold is None or time_window_seconds is None:
                        logs['actions']['validations']['action_configuration'].append(f'{action_name} must have "is_enabled", "threshold", "time_window_seconds"')
                        continue
                    if not isinstance(is_enabled, bool):
                        logs['actions']['validations']['action_configuration'].append(f'{action_name} "is_enabled" must be a <boolean>')
                        continue
                    if not isinstance(threshold, int) or not isinstance(time_window_seconds, int):
                        logs['actions']['validations']['action_configuration'].append(f'{action_name} "threshold", "time_window_seconds" must be <integer>')
                        continue
                    if action_type == 'webhook':
                        url = action_configuration_json.get("url")
                        type = action_configuration_json.get("type")
                        method = action_configuration_json.get('method')
                        connection_timeout = action_configuration_json.get('connection_timeout')
                        data_read_timeout = action_configuration_json.get('data_read_timeout')
                        if not url or not type or not method or not connection_timeout or not data_read_timeout:
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} must have "url", "type", "method", "connection_timeout", "data_read_timeout"')
                            continue
                        if type not in ['default', 'custom']:
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} must in "default" or "custom" type')
                            continue
                        if type == 'custom':
                            body = action_configuration_json.get('body')
                            if not body:
                                logs['actions']['validations']['action_configuration'].append(f'{action_name} must have "body" when "type" is custom')
                                continue
                            if not isinstance(body, dict):
                                logs['actions']['validations']['action_configuration'].append(f'{action_name} must have "body" in JSON format')
                                continue
                        if method.lower() not in ['post', 'get', 'put', 'patch', 'delete']:
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "method" must be in [POST, GET, PUT, PATCH, DELETE]')
                        if not isinstance(connection_timeout, int) or not isinstance(data_read_timeout, int):
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "connection_timeout", "data_read_timeout" must be <integer>')
                            continue
                        connection_timeout = int(connection_timeout)
                        data_read_timeout = int(data_read_timeout)
                        if connection_timeout <= 1 or data_read_timeout < 3:
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "connection_timeout" must be greater than 1 and "data_read_timeout" must be greater or equal to 3')
                            continue
                        try:
                            headers = {"Content-Type": "application/json"}
                            response = requests.get(url, headers=headers, json={}, timeout=(connection_timeout, data_read_timeout))
                            if response.status_code != 200:
                                logs['actions']['validations']['action_configuration'].append(f'{action_name} "url" test failed with status code: {str(response.status_code)}')
                                continue
                        except:
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} GET request to webhook for testing fail')
                            continue
                        logs['actions']['passed'].append(f'{action_name}')
                        response_elasticsearch.index(index='analyzer-actions', document={
                            'action_name': action_name,
                            'action_type': 'webhook',
                            'action_configuration': action_configuration
                        })
                        while True:
                            action_name_created = response_elasticsearch.search(index='analyzer-actions', query={
                                'term': {
                                    'action_name.keyword': action_name
                                }
                            }, size=ES_MAX_RESULT).raw
                            if action_name_created['hits']['hits'].__len__() > 0:
                                break
                    if action_type == 'email':
                        to = action_configuration_json.get('to')
                        subject = action_configuration_json.get('subject')
                        type = action_configuration_json.get('type')
                        body = action_configuration_json.get('body')
                        smtp = action_configuration_json.get('smtp')
                        if not all([to, subject, type, smtp]):
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} must have "to", "subject", "type", "smtp"')
                            continue
                        if not isinstance(to, str):
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "to" must be a <string>')
                            continue
                        if not isinstance(subject, str):
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "subject" must be a <string>')
                            continue
                        if not isinstance(type, str):
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "type" must be a <string>')
                            continue
                        if not isinstance(smtp, dict):
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "smtp" must be a <json>')
                            continue
                        if type not in ['default', 'custom']:
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "type" must in ["default", "custom"]')
                            continue
                        if type == 'custom':
                            if not body:
                                logs['actions']['validations']['action_configuration'].append(f'{action_name} must have "body" when "type" is custom')
                                continue
                            if not isinstance(body, dict):
                                logs['actions']['validations']['action_configuration'].append(f'{action_name} must have "body" in JSON format')
                                continue
                        smtp_host = smtp.get('host')
                        smtp_port = smtp.get('port')
                        smtp_username = smtp.get('username')
                        smtp_password = smtp.get('password')
                        if not all([smtp_host, smtp_port, smtp_username, smtp_password]):
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} must have "host", "port", "username", "password" for "smtp"')
                            continue
                        if not isinstance(smtp_host, str):
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "host" must be a <string> for "smtp"')
                            continue
                        if not isinstance(smtp_port, int):
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "port" must be a <integer> for "smtp"')
                            continue
                        if not isinstance(smtp_username, str):
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "username" must be a <string> for "smtp"')
                            continue
                        if not isinstance(smtp_password, str):
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "password" must be a <string> for "smtp"')
                            continue
                        email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
                        if not re.match(email_regex, smtp_username) or not re.match(email_regex, to):
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "username" or "to" must be email format')
                            continue
                        try:
                            message = MIMEMultipart()
                            message['From'] = smtp_username
                            message['To'] = to
                            message['Subject'] = subject
                            message.attach(MIMEText('Test Email credential successfully'))
                            if smtp_port == 465:
                                server = smtplib.SMTP_SSL(smtp_host, smtp_port)
                            else:
                                server = smtplib.SMTP(smtp_host, smtp_port)
                                server.starttls()
                            server.login(smtp_username, smtp_password)
                            server.sendmail(smtp_username, to, message.as_string())
                            server.quit()
                        except:
                            logs['actions']['validations']['action_configuration'].append(f'{action_name} "smtp" wrong configuration, send email fail for testing')
                            continue
                        logs['actions']['passed'].append(f'{action_name}')
                        response_elasticsearch.index(index='analyzer-actions', document={
                            'action_name': action_name,
                            'action_type': 'email',
                            'action_configuration': action_configuration
                        })
                        while True:
                            action_name_created = response_elasticsearch.search(index='analyzer-actions', query={
                                'term': {
                                    'action_name.keyword': action_name
                                }
                            }, size=ES_MAX_RESULT).raw
                            if action_name_created['hits']['hits'].__len__() > 0:
                                break
        if rules is not None:
            if not isinstance(rules, list):
                logs['rules']['datatype'] = 'Wrong, must be <list>'
            else:
                for rule in rules:
                    rule_holder = []
                    rule_type = rule.get('rule_type')
                    includes = rule.get('includes')
                    definitions = rule.get('definitions')
                    if not rule_type or not definitions:
                        logs['rules']['fields'].append(f'Missing "rule_type", "includes", "definitions"')
                        continue
                    if not isinstance(rule_type, str):
                        logs['rules']['validations']['rule_type'].append(f'"rule_type" must be a <string>')
                        continue
                    if rule_type in ['SQLI', 'XSS', 'FU']:
                        logs['rules']['validations']['rule_type'].append(f'{rule_type} can\'t in ["SQLI", "XSS", "FU"]')
                        continue
                    if includes is not None:
                        if not isinstance(includes, list):
                            logs['rules']['validations']['includes'].append(f'{rule_type} "include" must be a <list>')
                            continue
                        for include in includes:
                            elasticsearch_include = response_elasticsearch.search(index='analyzer-rules', query={
                                'term': {
                                    'rule_type.keyword': include
                                }
                            }, size=ES_MAX_RESULT)
                            if elasticsearch_include.raw['hits']['hits'].__len__() == 0:
                                logs['rules']['validations']['includes'].append(f'{rule_type} {include} "include" is not exist')
                                continue
                            for include in elasticsearch_include.raw['hits']['hits']:
                                rule_holder.append((include['_source']['rule_execution'], include['_source']['rule_description']))
                    if not isinstance(definitions, list):
                        logs['rules']['validations']['definitions'].append(f'{rule_type} "definitions" must be a <list>')
                        continue
                    for definition in definitions:
                        rule_execution = self.normalize_string(text=definition.get('rule_execution'))
                        rule_description = self.normalize_string(text=definition.get('rule_description'), is_yara=True)
                        if not rule_execution or not rule_description:
                            logs['rules']['validations']['definitions'].append(f'{rule_type} both of "rule_execution" and "rule_description" required')
                            continue
                        response_elasticsearch.index(index='analyzer-rules', document={
                            'rule_type': rule_type,
                            'rule_execution': rule_execution,
                            'rule_description': rule_description
                        })
                    for rule_hold in rule_holder:
                        response_elasticsearch.index(index='analyzer-rules', document={
                            'rule_type': rule_type,
                            'rule_execution': rule_hold[0],
                            'rule_description':rule_hold[1]
                        })
                    logs['rules']['passed'].append(f'{rule_description}')
                    while True:
                        rule_type_created = response_elasticsearch.search(index='analyzer-rules', query={
                            'term': {
                                'rule_type.keyword': rule_type
                            }
                        }, size=ES_MAX_RESULT).raw
                        if rule_type_created['hits']['hits'].__len__() > 0:
                            break
        if yaras is not None:
            if not isinstance(yaras, list):
                logs['yaras']['datatype'] = 'Wrong, must be <list>'
            else:
                for each_yara in yaras:
                    yara_rule_original = each_yara.get('yara_rule')
                    yara_description_original = each_yara.get('yara_description')
                    if not yara_rule_original or not yara_description_original:
                        logs['yaras']['fields'].append(f'Missing "yara_rule", "yara_description"')
                        continue
                    if not isinstance(yara_rule_original, str):
                        logs['yaras']['validations']['yara_rule'].append('"yara_rule" must be a <string>')
                        continue
                    if not isinstance(yara_description_original, str):
                        logs['yaras']['validations']['yara_description'].append('"yara_description" must be a <string>')
                        continue
                    yara_rule = self.normalize_string(text=yara_rule_original, is_yara=True)
                    yara_description = self.normalize_string(text=yara_description_original, is_yara=True)
                    try:
                        yara.compile(source=yara_rule)
                    except:
                        logs['yaras']['validations']['yara_rule'].append(f'{yara_rule} compiled error')
                        continue
                    logs['yaras']['passed'].append(f'{yara_description}')
                    response_elasticsearch.index(index='analyzer-yaras', document={
                        'yara_rule': yara_rule,
                        'yara_description': yara_description,
                        'yara_rule_original': yara_rule_original,
                        'yara_description_original': yara_description_original
                    })
        if sqlis is not None:
            if not isinstance(sqlis, list):
                logs['sqlis']['datatype'] = 'Wrong, must be <list>'
            else:
                for sqli in sqlis:
                    rule_name = sqli.get('rule_name')
                    is_enabled = sqli.get('is_enabled')
                    target_field = sqli.get('target_field')
                    ip_root_cause_field = sqli.get('ip_root_cause_field')
                    regex_matcher = sqli.get('regex_matcher')
                    rule_library = sqli.get('rule_library')
                    action = sqli.get('action')
                    if not rule_name or not target_field or not ip_root_cause_field:
                        logs['sqlis']['fields'].append(f'Missing "rule_name", "target_field", "ip_root_cause_field"')
                        continue
                    if not isinstance(rule_name, str):
                        logs['sqlis']['validations']['rule_name'].append(f'"rule_name" must be a <string>')
                        continue
                    if is_enabled is not None:
                        if not isinstance(is_enabled, bool):
                            logs['sqlis']['validations']['is_enabled'].append(f'{rule_name} "is_enabled" must be a <boolean>')
                            continue
                    else:
                        is_enabled = True
                    if not isinstance(target_field, str):
                        logs['sqlis']['validations']['target_field'].append(f'{rule_name} "target_field" must be a <string>')
                        continue
                    if not isinstance(ip_root_cause_field, str):
                        logs['sqlis']['validations']['ip_root_cause_field'].append(f'{rule_name} "ip_root_cause_field" must be a <string>')
                        continue
                    if not isinstance(regex_matcher, str):
                        logs['sqlis']['validations']['regex_matcher'].append(f'{rule_name} "regex_matcher" must be a <string> or <empty_string>')
                        continue
                    rule_names = []
                    for sqli_rule_name in sqlis:
                        if sqli_rule_name['rule_name'] != rule_name:
                            rule_names.append(sqli_rule_name['rule_name'])
                    if rule_name in rule_names:
                        logs['sqlis']['validations']['rule_name'].append(f'{rule_name} is exist in your YAML file')
                        continue
                    sqli_list = response_elasticsearch.search(index='analyzer-sqlis', query={
                        'term': {
                            'rule_name.keyword': rule_name
                        }
                    }, size=ES_MAX_RESULT).raw
                    if sqli_list['hits']['hits'].__len__() > 0:
                        logs['sqlis']['validations']['rule_name'].append(f'{rule_name} "rule_name" is exist is Elasticsearch')
                        continue
                    if regex_matcher.__len__() == 0 and rule_library is None:
                        logs['sqlis']['validations']['regex_matcher'].append(f'{rule_name} "regex_matcher" cannot be left blank if "rule_library" is not used and vice versa')
                        logs['sqlis']['validations']['rule_library'].append(f'{rule_name} "regex_matcher" cannot be left blank if "rule_library" is not used and vice versa')
                        continue
                    if regex_matcher.__len__() > 0:
                        try:
                            re.compile(pattern=regex_matcher)
                        except:
                            logs['sqlis']['validations']['regex_matcher'].append(f'{rule_name} "regex_matcher" is invalid regex syntax')
                            continue
                    if rule_library is not None:
                        rule_list = response_elasticsearch.search(index='analyzer-rules', query={
                            'term': {
                                'rule_type.keyword': rule_library
                            }
                        }).raw
                        if rule_list['hits']['hits'].__len__() == 0:
                            logs['sqlis']['validations']['rule_library'].append(f'{rule_name} "rule_library" is not exist')
                            continue
                    action_id = None
                    if action is not None:
                        action_list = response_elasticsearch.search(index='analyzer-actions', query={
                            'term': {
                                'action_name.keyword': action
                            }
                        }, size=ES_MAX_RESULT).raw
                        if action_list['hits']['hits'].__len__() == 0:
                            logs['sqlis']['validations']['action'].append(f'{rule_name} "action" is not exist')
                            continue
                        action_id = action_list['hits']['hits'][0]['_id']
                    response_elasticsearch.index(index='analyzer-sqlis', document={
                        'rule_name': rule_name,
                        'is_enabled': is_enabled,
                        'target_field': target_field,
                        'ip_root_cause_field': ip_root_cause_field,
                        'regex_matcher': regex_matcher,
                        'rule_library': rule_library,
                        'action_id': action_id,
                        'type_attack': 'sqli'
                    })
                    response_elasticsearch.index(index='analyzer-results', document={
                        'analyzer': 'SQLIs',
                        'reference': rule_name,
                        'match_count': 0,
                        'execution_count': 0,
                        'logs': '{}'
                    })
                    logs['sqlis']['passed'].append(f'{rule_name}')
        if xsss is not None:
            if not isinstance(xsss, list):
                logs['xsss']['datatype'] = 'Wrong, must be <list>'
            else:
                for xss in xsss:
                    rule_name = xss.get('rule_name')
                    is_enabled = xss.get('is_enabled')
                    target_field = xss.get('target_field')
                    ip_root_cause_field = xss.get('ip_root_cause_field')
                    regex_matcher = xss.get('regex_matcher')
                    rule_library = xss.get('rule_library')
                    action = xss.get('action')
                    if not rule_name or not target_field or not ip_root_cause_field:
                        logs['xsss']['fields'].append(f'Missing "rule_name", "target_field", "ip_root_cause_field"')
                        continue
                    if not isinstance(rule_name, str):
                        logs['xsss']['validations']['rule_name'].append(f'"rule_name" must be a <string>')
                        continue
                    if is_enabled is not None:
                        if not isinstance(is_enabled, bool):
                            logs['xsss']['validations']['is_enabled'].append(f'{rule_name} "is_enabled" must be a <boolean>')
                            continue
                    else:
                        is_enabled = True
                    if not isinstance(target_field, str):
                        logs['xsss']['validations']['target_field'].append(f'{rule_name} "target_field" must be a <string>')
                        continue
                    if not isinstance(ip_root_cause_field, str):
                        logs['xsss']['validations']['ip_root_cause_field'].append(f'{rule_name} "ip_root_cause_field" must be a <string>')
                        continue
                    if not isinstance(regex_matcher, str):
                        logs['xsss']['validations']['regex_matcher'].append(f'{rule_name} "regex_matcher" must be a <string> or <empty_string>')
                        continue
                    rule_names = []
                    for xss_rule_name in xsss:
                        if xss_rule_name['rule_name'] != rule_name:
                            rule_names.append(xss_rule_name['rule_name'])
                    if rule_name in rule_names:
                        logs['xsss']['validations']['rule_name'].append(f'{rule_name} is exist in your YAML file')
                        continue
                    xss_list = response_elasticsearch.search(index='analyzer-xsss', query={
                        'term': {
                            'rule_name.keyword': rule_name
                        }
                    }, size=ES_MAX_RESULT).raw
                    if xss_list['hits']['hits'].__len__() > 0:
                        logs['xsss']['validations']['rule_name'].append(f'{rule_name} "rule_name" is exist is Elasticsearch')
                        continue
                    if regex_matcher.__len__() == 0 and rule_library is None:
                        logs['xsss']['validations']['regex_matcher'].append(f'{rule_name} "regex_matcher" cannot be left blank if "rule_library" is not used and vice versa')
                        logs['xsss']['validations']['rule_library'].append(f'{rule_name} "regex_matcher" cannot be left blank if "rule_library" is not used and vice versa')
                        continue
                    if regex_matcher.__len__() > 0:
                        try:
                            re.compile(pattern=regex_matcher)
                        except:
                            logs['xsss']['validations']['regex_matcher'].append(f'{rule_name} "regex_matcher" is invalid regex syntax')
                            continue
                    if rule_library is not None:
                        rule_list = response_elasticsearch.search(index='analyzer-rules', query={
                            'term': {
                                'rule_type.keyword': rule_library
                            }
                        }).raw
                        if rule_list['hits']['hits'].__len__() == 0:
                            logs['xsss']['validations']['rule_library'].append(f'{rule_name} "rule_library" is not exist')
                            continue
                    action_id = None
                    if action is not None:
                        action_list = response_elasticsearch.search(index='analyzer-actions', query={
                            'term': {
                                'action_name.keyword': action
                            }
                        }, size=ES_MAX_RESULT).raw
                        if action_list['hits']['hits'].__len__() == 0:
                            logs['xsss']['validations']['action'].append(f'{rule_name} "action" is not exist')
                            continue
                        action_id = action_list['hits']['hits'][0]['_id']
                    response_elasticsearch.index(index='analyzer-xsss', document={
                        'rule_name': rule_name,
                        'is_enabled': is_enabled,
                        'target_field': target_field,
                        'ip_root_cause_field': ip_root_cause_field,
                        'regex_matcher': regex_matcher,
                        'rule_library': rule_library,
                        'action_id': action_id,
                        'type_attack': 'xss'
                    })
                    response_elasticsearch.index(index='analyzer-results', document={
                        'analyzer': 'XSSs',
                        'reference': rule_name,
                        'match_count': 0,
                        'execution_count': 0,
                        'logs': '{}'
                    })
                    logs['xsss']['passed'].append(f'{rule_name}')
        if fus is not None:
            if not isinstance(fus, list):
                logs['fus']['datatype'] = 'Wrong, must be <list>'
            else:
                for fu in fus:
                    rule_name = fu.get('rule_name')
                    is_enabled = fu.get('is_enabled')
                    target_field = fu.get('target_field')
                    ip_root_cause_field = fu.get('ip_root_cause_field')
                    regex_matcher = fu.get('regex_matcher')
                    rule_library = fu.get('rule_library')
                    yara_rule_intergration = fu.get('yara_rule_intergration')
                    action = fu.get('action')
                    if not rule_name or not target_field or not ip_root_cause_field:
                        logs['fus']['fields'].append(f'Missing "rule_name", "target_field", "ip_root_cause_field"')
                        continue
                    if not isinstance(rule_name, str):
                        logs['fus']['validations']['rule_name'].append(f'"rule_name" must be a <string>')
                        continue
                    if is_enabled is not None:
                        if not isinstance(is_enabled, bool):
                            logs['fus']['validations']['is_enabled'].append(f'{rule_name} "is_enabled" must be a <boolean>')
                            continue
                    else:
                        is_enabled = True
                    if not isinstance(target_field, str):
                        logs['fus']['validations']['target_field'].append(f'{rule_name} "target_field" must be a <string>')
                        continue
                    if not isinstance(ip_root_cause_field, str):
                        logs['fus']['validations']['ip_root_cause_field'].append(f'{rule_name} "ip_root_cause_field" must be a <string>')
                        continue
                    if not isinstance(regex_matcher, str):
                        logs['fus']['validations']['regex_matcher'].append(f'{rule_name} "regex_matcher" must be a <string> or <empty_string>')
                        continue
                    rule_names = []
                    for fu_rule_name in fus:
                        if fu_rule_name['rule_name'] != rule_name:
                            rule_names.append(fu_rule_name['rule_name'])
                    if rule_name in rule_names:
                        logs['fus']['validations']['rule_name'].append(f'{rule_name} is exist in your YAML file')
                        continue
                    fu_list = response_elasticsearch.search(index='analyzer-fus', query={
                        'term': {
                            'rule_name.keyword': rule_name
                        }
                    }, size=ES_MAX_RESULT).raw
                    if fu_list['hits']['hits'].__len__() > 0:
                        logs['fus']['validations']['rule_name'].append(f'{rule_name} "rule_name" is exist is Elasticsearch')
                        continue
                    if regex_matcher.__len__() == 0 and rule_library is None:
                        logs['fus']['validations']['regex_matcher'].append(f'{rule_name} "regex_matcher" cannot be left blank if "rule_library" is not used and vice versa')
                        logs['fus']['validations']['rule_library'].append(f'{rule_name} "regex_matcher" cannot be left blank if "rule_library" is not used and vice versa')
                        continue
                    if regex_matcher.__len__() > 0:
                        try:
                            re.compile(pattern=regex_matcher)
                        except:
                            logs['fus']['validations']['regex_matcher'].append(f'{rule_name} "regex_matcher" is invalid regex syntax')
                            continue
                    if rule_library is not None:
                        rule_list = response_elasticsearch.search(index='analyzer-rules', query={
                            'term': {
                                'rule_type.keyword': rule_library
                            }
                        }).raw
                        if rule_list['hits']['hits'].__len__() == 0:
                            logs['fus']['validations']['rule_library'].append(f'{rule_name} "rule_library" is not exist')
                            continue
                    if yara_rule_intergration is not None:
                        if not isinstance(yara_rule_intergration, bool):
                            logs['fus']['validations']['yara_rule_intergration'].append(f'{rule_name} "yara_rule_intergration" must be a <boolean>')
                            continue
                    action_id = None
                    if action is not None:
                        action_list = response_elasticsearch.search(index='analyzer-actions', query={
                            'term': {
                                'action_name.keyword': action
                            }
                        }, size=ES_MAX_RESULT).raw
                        if action_list['hits']['hits'].__len__() == 0:
                            logs['fus']['validations']['action'].append(f'{rule_name} "action" is not exist')
                            continue
                        action_id = action_list['hits']['hits'][0]['_id']
                    response_elasticsearch.index(index='analyzer-fus', document={
                        'rule_name': rule_name,
                        'is_enabled': is_enabled,
                        'target_field': target_field,
                        'ip_root_cause_field': ip_root_cause_field,
                        'regex_matcher': regex_matcher,
                        'rule_library': rule_library,
                        'yara_rule_intergration': yara_rule_intergration,
                        'action_id': action_id,
                        'type_attack': 'fu'
                    })
                    response_elasticsearch.index(index='analyzer-results', document={
                        'analyzer': 'FUs',
                        'reference': rule_name,
                        'match_count': 0,
                        'execution_count': 0,
                        'logs': '{}'
                    })
                    logs['fus']['passed'].append(f'{rule_name}')
        if wordlists is not None:
            if not isinstance(wordlists, list):
                logs['wordlists']['datatype'] = 'Wrong, must be <list>'
            else:
                for wordlist in wordlists:
                    wordlist_name = wordlist.get('wordlist_name')
                    contents = wordlist.get('content')
                    if not all([wordlist_name, contents]):
                        logs['wordlists']['fields'].append(f'Missing "wordlist_name", "content"')
                        continue
                    if sum(1 for d in wordlists if wordlist_name in d.values()) > 1:
                        logs['wordlists']['validations']['wordlist_name'].append(f'{wordlist_name} "wordlist_name" is exist in your YAML file')
                        continue
                    if not isinstance(wordlist_name, str):
                        logs['wordlists']['validations']['wordlist_name'].append(f'{wordlist_name} must be (string)')
                        continue
                    if not isinstance(contents, list):
                        logs['wordlists']['validations']['content'].append(f'"content" of {wordlist_name} must be (list)')
                        continue
                    if not wordlist_name:
                        logs['wordlists']['validations']['wordlist_name'].append(f'{wordlist_name} can\'t be empty')
                        continue
                    if wordlist_name in [word['key'] for word in response_elasticsearch.search(index='analyzer-wordlists', body={
                        "aggs":{
                            "unique_names": {
                                "terms": {
                                    "field": "wordlist_name.keyword"
                                }
                            }
                        },
                        "_source": False
                    }, size=ES_MAX_RESULT).raw['aggregations']['unique_names']['buckets']]:
                        logs['wordlists']['validations']['wordlist_name'].append(f'{wordlist_name} "wordlist_name" is exist in Elasticsearch')
                        continue
                    for content in contents:
                        if content:
                            response_elasticsearch.index(index='analyzer-wordlists', document={
                                'wordlist_name': wordlist_name,
                                'content': content
                            })
                    logs['wordlists']['passed'].append(f'{wordlist_name}')
        return {
            'type': 'resources',
            'data': logs,
            'reason': 'Success'
        }

    def normalize_string(self, text: str, is_yara: bool = False) -> str:
        if is_yara is True:
            lines = text.strip().split("\n")        
            formatted_lines = []
            for line in lines:
                formatted_lines.append(line.strip())
            yara_rule = " ".join(formatted_lines)
            return yara_rule
        return re.sub(r'\s+', '', text).replace('\n', '').strip()
