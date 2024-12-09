from datetime import datetime
from flask import Blueprint, request
from json import loads, dumps
import html
from urllib.parse import parse_qs
from .operations import xss_operation_blueprint
from ..storage import response_elasticsearch, ES_MAX_RESULT
from ..functions import get_value_from_json, hex_escape_to_char, parse_multipart_form_data, parse_path, is_valid_regex, re, traverse_json, execute_action, check_threshold, decode_hex_escaped_string


xss_main_blueprint = Blueprint(name='xss_main_blueprint', import_name=__name__)

xss_main_blueprint.register_blueprint(blueprint=xss_operation_blueprint, url_prefix='/xsss')

xss_analyzer_blueprint = Blueprint(name='xss_analyzer_blueprint', import_name=__name__)


@xss_analyzer_blueprint.route('/xsss/<string:rule_name>', methods=['POST'])
def xss_analyzer_endpoint(rule_name: str):
    if response_elasticsearch.ping() is False:
        return {
            'type': 'xsss',
            'data': None,
            'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
        }, 500
    xss = response_elasticsearch.search(index='analyzer-xsss', query={'term': {'rule_name.keyword': rule_name}}, size=ES_MAX_RESULT)
    xss_result = xss.raw['hits']['hits']
    if xss_result.__len__() != 1:
        return {
            'type': 'xss_analyzer',
            'data': None,
            'reason': 'NotFound: Rule Name not found'
        }, 404
    xss_analyzer = xss_result[0]
    if xss_analyzer['_source']['is_enabled'] is False:
        return {
            'type': 'xss_analyzer',
            'data': None,
            'reason': 'Success: This analyzer is disabled'
        }
    try:
        loads(request.data)
    except:
        return {
            'type': 'xss_analyzer',
            'data': None,
            'reason': 'BadRequest: Body must be JSON'
        }, 400
    target_field = xss_analyzer['_source']['target_field']
    ip_root_cause_field = xss_analyzer['_source']['ip_root_cause_field']
    regex_matcher = xss_analyzer['_source']['regex_matcher']
    rule_library = xss_analyzer['_source']['rule_library']
    action_id = xss_analyzer['_source']['action_id']
    logs = {
        '[Warning]': [],
        '[Error]': [],
        '[Info]': []
    }
    result = None
    json = request.get_json()
    rules = []
    ip_root_cause_field_value = '<>'
    ip_root_cause_field_validation = parse_path(path=ip_root_cause_field)
    all_fields = traverse_json(data=json)
    if ip_root_cause_field_validation is None or str(type(ip_root_cause_field_validation)) != "<class 'str'>":
        logs['[Warning]'].append({
            'Analyzers': {
                'message': 'IP Root Cause Field is invalid format',
                'pattern': ip_root_cause_field
            }
        })
    else:
        ip_root_cause_field_value = get_value_from_json(data=json, path=ip_root_cause_field)
        if ip_root_cause_field_value is None or str(type(ip_root_cause_field_value)) != "<class 'str'>":
            logs['[Warning]'].append({
                'Analyzers': {
                    'message': 'IP Root Cause Field is not exist or invalid data type',
                    'pattern': ip_root_cause_field
                }
            })
    if regex_matcher.__len__() > 0:
        if is_valid_regex(pattern=regex_matcher) is False:
            logs['[Warning]'].append({
                'Analyzers': {
                    'message': 'Regex Matcher is invalid',
                    'pattern': regex_matcher
                }
            })
        else:
            rules.append(re.compile(rf'{regex_matcher}'))
    if rule_library is not None:
        rule_libraries = response_elasticsearch.search(index='analyzer-rules', query={'match_phrase': {'rule_type': rule_library}}, size=ES_MAX_RESULT)
        for library in rule_libraries.raw['hits']['hits']:
            if is_valid_regex(pattern=library['_source']['rule_execution']) is False:
                logs['[Warning]'].append({
                    'Rule Libraries': {
                        'message': f'Rule id {library['_id']} is invalid from {library['_source']['rule_type']}',
                        'pattern': library['_source']['rule_execution']
                    }
                })
            else:
                rules.append(re.compile(rf'{library['_source']['rule_execution']}'))
    if target_field.__len__() == 0:
        if all_fields.__len__() > 0:
            flag = False
            for field in all_fields:
                for key, value in field.items():
                    value = decode_hex_escaped_string(input_string=str(value))
                    for rule in rules:
                        if rule.search(value):
                            root_cause_value = hex_escape_to_char(string=value)
                            try:
                                root_cause_value = parse_multipart_form_data(raw_data=root_cause_value)
                            except:
                                try:
                                    root_cause_value: dict = loads(root_cause_value)
                                except:
                                    try:
                                        parsed_data = parse_qs(root_cause_value)
                                        if not root_cause_value:
                                            raise
                                        root_cause_value = {key: value[0] for key, value in parsed_data.items()}
                                    except:
                                        logs['[Warning]'].append({
                                            'Analyzers': {
                                                'message': '"target_value" field not a valid in ["multipart/form-data", "application/json", "application/x-www-form-urlencoded"], original accepted',
                                                'pattern': html.escape(root_cause_value)
                                            }
                                        })
                            if isinstance(root_cause_value, dict):
                                for _, _value in root_cause_value.items():
                                    if rule.search(_value):
                                        root_cause_value = _value
                                        break
                            result = {
                                '_message_': f'Detected from {rule_name} analyzer',
                                'field_name': key,
                                'field_value': root_cause_value,
                                'by_rule': rule.pattern,
                                '_ip_root_cause_': ip_root_cause_field_value
                            }
                            flag = True
                            break
                    if flag:
                        break
                if flag:
                    break
            if result is not None:
                response_elasticsearch.index(index='analyzer-errorlogs', document={
                    'analyzer': 'xss',
                    'reference': rule_name,
                    'errorlog': dumps(logs)
                })
                response_elasticsearch.index(index='analyzer-results', document={
                    'analyzer': 'xss',
                    'reference': rule_name,
                    'type': 'match_count'
                })
                if action_id is not None:
                    try:
                        action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
                    except:
                        return {
                            'type': 'xss_analyzer',
                            'data': None,
                            'reason': 'InternalServerError: Action found but can\'t load, abort error'
                        }, 500
                    timestamp = datetime.now().timestamp()
                    action_timestamp = response_elasticsearch.index(index='analyzer-action-timestamps', document={
                        "analyzer": 'XSSs',
                        "rule_name": rule_name,
                        "action_name": action.raw['_source']['action_name'],
                        "timestamp": int(timestamp)
                    })
                    if check_threshold(
                        analyzer='XSSs', 
                        rule_name=rule_name, 
                        action_name=action.raw['_source']['action_name'], 
                        action_configuration=loads(action.raw['_source']['action_configuration']), 
                        action_timestamp_id=action_timestamp['_id']
                    ) is True:
                        if execute_action(action_type=action.raw['_source']['action_type'], action_configuration=loads(action.raw['_source']['action_configuration']), virtual_variable_list={
                            'id': xss_analyzer['_id'],
                            'rule_name': xss_analyzer['_source']['rule_name'],
                            'is_enabled': xss_analyzer['_source']['is_enabled'],
                            'target_field': xss_analyzer['_source']['target_field'],
                            'target_value': all_fields,
                            'ip_root_cause_field': xss_analyzer['_source']['ip_root_cause_field'],
                            'ip_root_cause_value': ip_root_cause_field_value,
                            'regex_matcher': xss_analyzer['_source']['regex_matcher'],
                            'rule_library': xss_analyzer['_source']['rule_library'],
                            'action': action.raw['_source']['action_name'],
                            'result': result
                        }, default_body=result, ip_root_cause=ip_root_cause_field_value) is False:
                            logs['[Error]'].append({
                                'Actions': {
                                    'message': 'Action perform fail with some reasons',
                                    'pattern': action['_source']['action_configuration']
                                }
                            })
                            response_elasticsearch.index(index='analyzer-errorlogs', document={
                                'analyzer': 'xss',
                                'reference': rule_name,
                                'errorlog': dumps(logs)
                            })
                        else:
                            response_elasticsearch.index(index='analyzer-results', document={
                                'analyzer': 'xss',
                                'reference': rule_name,
                                'type': 'execution_count'
                            })
                return {
                    'type': 'xss_analyzer',
                    'data': result,
                    'reason': 'Success: Potential Cross Site Scripting detected'
                } 
            return {
                'type': 'xss_analyzer',
                'data': None,
                'reason': 'Success: Clean log'
            }
        else:
            return {
                'type': 'xss_analyzer',
                'data': None,
                'reason': 'Success: No log'
            }
    else:
        target_field_path = parse_path(path=target_field)
        if str(type(target_field_path)) == "<class 'str'>":
            json_value = get_value_from_json(data=json, path=target_field)
            if json_value is not None:
                json_value_str = decode_hex_escaped_string(input_string=str(json_value))
                for rule in rules:
                    if rule.search(json_value_str):
                        root_cause_value = hex_escape_to_char(string=json_value_str)
                        try:
                            root_cause_value = parse_multipart_form_data(raw_data=root_cause_value)
                        except:
                            try:
                                root_cause_value: dict = loads(root_cause_value)
                            except:
                                try:
                                    parsed_data = parse_qs(root_cause_value)
                                    if not root_cause_value:
                                        raise
                                    root_cause_value = {key: value[0] for key, value in parsed_data.items()}
                                except:
                                    logs['[Warning]'].append({
                                        'Analyzers': {
                                            'message': '"target_value" field not a valid in ["multipart/form-data", "application/json", "application/x-www-form-urlencoded"], original accepted',
                                            'pattern': html.escape(root_cause_value)
                                        }
                                    })
                        if isinstance(root_cause_value, dict):
                            for _, _value in root_cause_value.items():
                                if rule.search(_value):
                                    root_cause_value = _value
                                    break
                        result = {
                            '_message_': f'Detected from {rule_name} analyzer',
                            'field_name': target_field,
                            'field_value': root_cause_value,
                            'by_rule': rule.pattern,
                            '_ip_root_cause_': ip_root_cause_field_value
                        }
                        break
                if result is not None:
                    response_elasticsearch.index(index='analyzer-errorlogs', document={
                        'analyzer': 'xss',
                        'reference': rule_name,
                        'errorlog': dumps(logs)
                    })
                    response_elasticsearch.index(index='analyzer-results', document={
                        'analyzer': 'xss',
                        'reference': rule_name,
                        'type': 'match_count'
                    })
                    if action_id is not None:
                        try:
                            action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
                        except:
                            return {
                                'type': 'xss_analyzer',
                                'data': None,
                                'reason': 'InternalServerError: Action found but can\'t load, abort error'
                            }, 500
                        timestamp = datetime.now().timestamp()
                        action_timestamp = response_elasticsearch.index(index='analyzer-action-timestamps', document={
                            "analyzer": 'XSSs',
                            "rule_name": rule_name,
                            "action_name": action.raw['_source']['action_name'],
                            "timestamp": int(timestamp)
                        })
                        if check_threshold(analyzer='XSSs', rule_name=rule_name, action_name=action.raw['_source']['action_name'], action_configuration=loads(action.raw['_source']['action_configuration']), action_timestamp_id=action_timestamp['_id']) is True:
                            if execute_action(action_type=action.raw['_source']['action_type'], action_configuration=loads(action.raw['_source']['action_configuration']), virtual_variable_list={
                                'id': xss_analyzer['_id'],
                                'rule_name': xss_analyzer['_source']['rule_name'],
                                'is_enabled': xss_analyzer['_source']['is_enabled'],
                                'target_field': xss_analyzer['_source']['target_field'],
                                'target_value': json_value_str,
                                'ip_root_cause_field': xss_analyzer['_source']['ip_root_cause_field'],
                                'ip_root_cause_value': ip_root_cause_field_value,
                                'regex_matcher': xss_analyzer['_source']['regex_matcher'],
                                'rule_library': xss_analyzer['_source']['rule_library'],
                                'action': action.raw['_source']['action_name'],
                                'result': result
                            }, default_body=result, ip_root_cause=ip_root_cause_field_value) is False:
                                logs['[Error]'].append({
                                    'Actions': {
                                        'message': 'Action perform fail with some reasons',
                                        'pattern': action.raw['_source']['action_configuration']
                                    }
                                })
                                response_elasticsearch.index(index='analyzer-errorlogs', document={
                                    'analyzer': 'xss',
                                    'reference': rule_name,
                                    'errorlog': dumps(logs)
                                })
                            else:
                                response_elasticsearch.index(index='analyzer-results', document={
                                    'analyzer': 'xss',
                                    'reference': rule_name,
                                    'type': 'execution_count'
                                })
                    return {
                        'type': 'xss_analyzer',
                        'data': result,
                        'reason': 'Success: Potential Cross Site Scripting detected'
                    }
                return {
                    'type': 'xss_analyzer',
                    'data': None,
                    'reason': 'Success: Clean log'
                }
            else:
                logs['[Info]'].append({
                    'message': 'Target Field is not exist, skipped',
                    'pattern': f'{target_field}'
                })
                response_elasticsearch.index(index='analyzer-errorlogs', document={
                    'analyzer': 'xss',
                    'reference': rule_name,
                    'errorlog': dumps(logs)
                })
        elif str(type(target_field_path)) == "<class 'list'>":
            target_field_value = []
            for path in target_field_path:
                path_value = get_value_from_json(data=json, path=path)
                target_field_value.append({
                    path: path_value
                })
            for path in target_field_path:
                json_value = get_value_from_json(data=json, path=path)
                if json_value is not None:
                    json_value_str = decode_hex_escaped_string(input_string=str(json_value))
                    for rule in rules:
                        if rule.search(json_value_str):
                            root_cause_value = hex_escape_to_char(string=json_value_str)
                            try:
                                root_cause_value = parse_multipart_form_data(raw_data=root_cause_value)
                            except:
                                try:
                                    root_cause_value: dict = loads(root_cause_value)
                                except:
                                    try:
                                        parsed_data = parse_qs(root_cause_value)
                                        if not root_cause_value:
                                            raise
                                        root_cause_value = {key: value[0] for key, value in parsed_data.items()}
                                    except:
                                        logs['[Warning]'].append({
                                            'Analyzers': {
                                                'message': '"target_value" field not a valid in ["multipart/form-data", "application/json", "application/x-www-form-urlencoded"], original accepted',
                                                'pattern': html.escape(root_cause_value)
                                            }
                                        })
                            if isinstance(root_cause_value, dict):
                                for _, _value in root_cause_value.items():
                                    if rule.search(_value):
                                        root_cause_value = _value
                                        break
                            result = {
                                '_message_': f'Detected from {rule_name} analyzer',
                                'field_name': path,
                                'field_value': root_cause_value,
                                'by_rule': rule.pattern,
                                '_ip_root_cause_': ip_root_cause_field_value
                            }
                            break
                    if result is not None:
                        response_elasticsearch.index(index='analyzer-errorlogs', document={
                            'analyzer': 'xss',
                            'reference': rule_name,
                            'errorlog': dumps(logs)
                        })
                        response_elasticsearch.index(index='analyzer-results', document={
                            'analyzer': 'xss',
                            'reference': rule_name,
                            'type': 'match_count'
                        })
                        if action_id is not None:
                            try:
                                action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
                            except:
                                return {
                                    'type': 'xss_analyzer',
                                    'data': None,
                                    'reason': 'InternalServerError: Action found but can\'t load, abort error'
                                }, 500
                            timestamp = datetime.now().timestamp()
                            action_timestamp= response_elasticsearch.index(index='analyzer-action-timestamps', document={
                                "analyzer": 'XSSs',
                                "rule_name": rule_name,
                                "action_name": action.raw['_source']['action_name'],
                                "timestamp": int(timestamp)
                            })
                            if check_threshold(analyzer='XSSs', rule_name=rule_name, action_name=action.raw['_source']['action_name'], action_configuration=loads(action.raw['_source']['action_configuration']), action_timestamp_id=action_timestamp['_id']) is True:
                                if execute_action(action_type=action.raw['_source']['action_type'], action_configuration=loads(action.raw['_source']['action_configuration']), virtual_variable_list={
                                    'id': xss_analyzer['_id'],
                                    'rule_name': xss_analyzer['_source']['rule_name'],
                                    'is_enabled': xss_analyzer['_source']['is_enabled'],
                                    'target_field': xss_analyzer['_source']['target_field'],
                                    'target_value': target_field_value,
                                    'ip_root_cause_field': xss_analyzer['_source']['ip_root_cause_field'],
                                    'ip_root_cause_value': ip_root_cause_field_value,
                                    'regex_matcher': xss_analyzer['_source']['regex_matcher'],
                                    'rule_library': xss_analyzer['_source']['rule_library'],
                                    'action': action.raw['_source']['action_name'],
                                    'result': result
                                }, default_body=result, ip_root_cause=ip_root_cause_field_value) is False:
                                    logs['[Error]'].append({
                                        'Actions': {
                                            'message': 'Action perform fail with some reasons',
                                            'pattern': action[3]
                                        }
                                    })
                                    response_elasticsearch.index(index='analyzer-errorlogs', document={
                                        'analyzer': 'xss',
                                        'reference': rule_name,
                                        'errorlog': dumps(logs)
                                    })
                                else:
                                    response_elasticsearch.index(index='analyzer-results', document={
                                        'analyzer': 'xss',
                                        'reference': rule_name,
                                        'type': 'execution_count'
                                    })
                        return {
                            'type': 'xss_analyzer',
                            'data': result,
                            'reason': 'Success: Potential Cross Site Scripting Injection detected'
                        }
                else:
                    logs['[Info]'].append({
                        'Analyzers': {
                            'message': 'Target Field is not exist, skipped',
                            'pattern': f'{path}'
                        }
                    })
                    response_elasticsearch.index(index='analyzer-errorlogs', document={
                        'analyzer': 'xss',
                        'reference': rule_name,
                        'errorlog': dumps(logs)
                    })
            return {
                'type': 'xss_analyzer',
                'data': None,
                'reason': 'Success: Clean log'
            }
        else:
            logs['[Error]'].append({
                'Analyzers': {
                    'message': 'Target Field is invalid format',
                    'pattern': f'{target_field}'
                }
            })
            response_elasticsearch.index(index='analyzer-errorlogs', document={
                'analyzer': 'xss',
                'reference': rule_name,
                'errorlog': dumps(logs)
            })
    return {
        'type': 'xss_analyzer',
        'data': None,
        'reason': 'Success'
    }