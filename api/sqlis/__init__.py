from flask import Blueprint, request
from json import loads
from .operations import sqli_operation_blueprint
from ..storage import response_elasticsearch
from ..functions import get_value_from_json, parse_path, is_valid_regex, re, traverse_json, execute_action


sqli_main_blueprint = Blueprint(name='sqli_main_blueprint', import_name=__name__)

sqli_main_blueprint.register_blueprint(blueprint=sqli_operation_blueprint, url_prefix='/sqlis')

sqli_analyzer_blueprint = Blueprint(name='sqli_analyzer_blueprint', import_name=__name__)


@sqli_analyzer_blueprint.route('/sqli/<string:rule_name>', methods=['POST'])
def sqli_analyzer_endpoint(rule_name: str):
    if response_elasticsearch.ping() is False:
        return {
            'type': 'xsss',
            'data': None,
            'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
        }, 500
    sqli = response_elasticsearch.search(index='analyzer-sqlis', query={'match_phrase': {'rule_name': rule_name}}, size=1000000000)
    sqli_result = sqli.raw['hits']['hits']
    if sqli_result.__len__() != 1:
        return {
            'type': 'sqli_analyzer',
            'data': None,
            'reason': 'NotFound: Rule Name not found'
        }, 404
    sqli_analyzer = sqli_result[0]
    if sqli_analyzer['_source']['is_enabled'] is False:
        return {
            'type': 'sqli_analyzer',
            'data': None,
            'reason': 'Success: This analyzer is disabled'
        }        
    try:
        loads(request.data)
    except:
        return {
            'type': 'sqli_analyzer',
            'data': None,
            'reason': 'Body must be JSON'
        }, 
    target_field = sqli_analyzer['_source']['target_field']
    ip_root_cause_field = sqli_analyzer['_source']['ip_root_cause_field']
    regex_matcher = sqli_analyzer['_source']['regex_matcher']
    rule_library = sqli_analyzer['_source']['rule_library']
    action_id = sqli_analyzer['_source']['action_id']
    error_logs = []
    result = None
    json = request.get_json()
    rules = []
    ip_root_cause_field_value = '<>'
    ip_root_cause_field_validation = parse_path(path=ip_root_cause_field)
    all_fields = traverse_json(data=json)
    if ip_root_cause_field_validation is None or str(type(ip_root_cause_field_validation)) != "<class 'str'>":
        error_logs.append({
            'message': 'IP Root Cause Field is invalid format',
            'pattern': ip_root_cause_field
        })
    else:
        ip_root_cause_field_value = get_value_from_json(data=json, path=ip_root_cause_field)
        if ip_root_cause_field_value is None or str(type(ip_root_cause_field_value)) != "<class 'str'>":
            error_logs.append({
                'message': 'IP Root Cause Field is not exist or invalid data type',
                'pattern': ip_root_cause_field
            })
    if regex_matcher.__len__() > 0:
        if is_valid_regex(pattern=regex_matcher) is False:
            error_logs.append({
                'message': 'Regex Matcher is invalid',
                'pattern': regex_matcher
            })
        else:
            rules.append(re.compile(rf'{regex_matcher}'))
    if rule_library is not None:
        rule_libraries = response_elasticsearch.search(index='analyzer-rules', query={'match_phrase': {'rule_type': rule_library}}, size=1000000000)
        for library in rule_libraries.raw['hits']['hits']:
            if is_valid_regex(pattern=library['_source']['rule_execution']) is False:
                error_logs.append({
                    'message': f'Rule id {library['_id']} is invalid from {library['_source']['rule_type']}',
                    'pattern': library['_source']['rule_execution']
                })
            else:
                rules.append(re.compile(rf'{library['_source']['rule_execution']}'))
    if target_field.__len__() == 0:
        if all_fields.__len__() > 0:
            flag = False
            for field in all_fields:
                for key, value in field.items():
                    for rule in rules:
                        if rule.search(str(value)):
                            result = {
                                'message': f'Detected from {rule_name} analyzer',
                                'field_name': key,
                                'field_value': value,
                                'by_rule': str(rule),
                                'ip_root_cause': ip_root_cause_field_value
                            }
                            flag = True
                            break
                    if flag:
                        break
                if flag:
                    break
            if result is not None:
                if action_id is not None:
                    try:
                        action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
                    except:
                        return {
                            'type': 'sqli_analyzer',
                            'data': None,
                            'reason': 'InternalServerError: Action found but can\'t load, abort error'
                        }, 500
                    if execute_action(action_type=action.raw['_source']['action_type'], action_configuration=loads(action.raw['_source']['action_configuration']), virtual_variable_list={
                        'id': sqli_analyzer['_id'],
                        'rule_name': sqli_analyzer['_source']['rule_name'],
                        'is_enabled': sqli_analyzer['_source']['is_enabled'],
                        'target_field': sqli_analyzer['_source']['target_field'],
                        'target_value': all_fields,
                        'ip_root_cause_field': sqli_analyzer['_source']['ip_root_cause_field'],
                        'ip_root_cause_value': ip_root_cause_field_value,
                        'regex_matcher': sqli_analyzer['_source']['regex_matcher'],
                        'rule_library': sqli_analyzer['_source']['rule_library'],
                        'action': action.raw['_source']['action_name'],
                        'result': result
                    }, default_body=result) is False:
                        error_logs.append({
                            'message': 'Action perform fail with some reasons',
                            'pattern': action['_source']['action_configuration']
                        })
            return {
                'type': 'sqli_analyzer',
                'data': result,
                'reason': 'Success: Potential SQL Injection detected'
            } if result is not None else {
                'type': 'sqli_analyzer',
                'data': None,
                'reason': 'Success: Clean log'
            }
        else:
            return {
                'type': 'sqli_analyzer',
                'data': None,
                'reason': 'Success: No log'
            }
    else:
        target_field_path = parse_path(path=target_field)
        if str(type(target_field_path)) == "<class 'str'>":
            json_value = get_value_from_json(data=json, path=target_field)
            if json_value is not None:
                json_value_str = str(json_value)
                for rule in rules:
                    if rule.search(json_value_str):
                        result = {
                            'message': f'Detected from {rule_name} analyzer',
                            'field_name': target_field,
                            'field_value': json_value_str,
                            'by_rule': str(rule),
                            'ip_root_cause': ip_root_cause_field_value
                        }
                        break
                if result is not None:
                    if action_id is not None:
                        try:
                            action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
                        except:
                            return {
                                'type': 'sqli_analyzer',
                                'data': None,
                                'reason': 'InternalServerError: Action found but can\'t load, abort error'
                            }, 500
                        if execute_action(action_type=action.raw['_source']['action_type'], action_configuration=loads(action.raw['_source']['action_configuration']), virtual_variable_list={
                            'id': sqli_analyzer['_id'],
                            'rule_name': sqli_analyzer['_source']['rule_name'],
                            'is_enabled': sqli_analyzer['_source']['is_enabled'],
                            'target_field': sqli_analyzer['_source']['target_field'],
                            'target_value': json_value_str,
                            'ip_root_cause_field': sqli_analyzer['_source']['ip_root_cause_field'],
                            'ip_root_cause_value': ip_root_cause_field_value,
                            'regex_matcher': sqli_analyzer['_source']['regex_matcher'],
                            'rule_library': sqli_analyzer['_source']['rule_library'],
                            'action': action.raw['_source']['action_name'],
                            'result': result
                        }, default_body=result) is False:
                            error_logs.append({
                                'message': 'Action perform fail with some reasons',
                                'pattern': action.raw['_source']['action_configuration']
                            })
                return {
                    'type': 'sqli_analyzer',
                    'data': result,
                    'reason': 'Success: Potential SQL Injection detected'
                } if result is not None else {
                    'type': 'sqli_analyzer',
                    'data': None,
                    'reason': 'Success: Clean log'
                }
            else:
                error_logs.append({
                    'message': 'Target Field is not exist',
                    'pattern': f'{target_field}'
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
                    json_value_str = str(json_value)
                    for rule in rules:
                        if rule.search(json_value_str):
                            result = {
                                'message': f'Detected from {rule_name} analyzer',
                                'field_name': path,
                                'field_value': json_value_str,
                                'by_rule': str(rule),
                                'ip_root_cause': ip_root_cause_field_value
                            }
                            break
                    if result is not None:
                        if action_id is not None:
                            try:
                                action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
                            except:
                                return {
                                    'type': 'sqli_analyzer',
                                    'data': None,
                                    'reason': 'InternalServerError: Action found but can\'t load, abort error'
                                }, 500
                            if execute_action(action_type=action.raw['_source']['action_type'], action_configuration=loads(action.raw['_source']['action_configuration']), virtual_variable_list={
                                'id': sqli_analyzer['_id'],
                                'rule_name': sqli_analyzer['_source']['rule_name'],
                                'is_enabled': sqli_analyzer['_source']['is_enabled'],
                                'target_field': sqli_analyzer['_source']['target_field'],
                                'target_value': target_field_value,
                                'ip_root_cause_field': sqli_analyzer['_source']['ip_root_cause_field'],
                                'ip_root_cause_value': ip_root_cause_field_value,
                                'regex_matcher': sqli_analyzer['_source']['regex_matcher'],
                                'rule_library': sqli_analyzer['_source']['rule_library'],
                                'action': action.raw['_source']['action_name'],
                                'result': result
                            }, default_body=result) is False:
                                error_logs.append({
                                    'message': 'Action perform fail with some reasons',
                                    'pattern': action[3]
                                })
                    return {
                        'type': 'sqli_analyzer',
                        'data': result,
                        'reason': 'Success: Potential SQL Injection detected'
                    } if result is not None else {
                        'type': 'sqli_analyzer',
                        'data': None,
                        'reason': 'Success: Clean log'
                    }
                else:
                    error_logs.append({
                        'message': 'Target Field is not exist',
                        'pattern': f'{path}'
                    })
        else:
            error_logs.append({
                'message': 'Target Field is invalid format',
                'pattern': f'{target_field}'
            })
    return {
        'type': 'sqli_analyzer',
        'data': None,
        'reason': 'Success'
    }