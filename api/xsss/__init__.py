from flask import Blueprint, request
from json import loads
from .operations import xss_operation_blueprint
from ..storage import response_elasticsearch, ES_MAX_RESULT
from ..functions import get_value_from_json, parse_path, is_valid_regex, re, traverse_json, execute_action


xss_main_blueprint = Blueprint(name='xss_main_blueprint', import_name=__name__)

xss_main_blueprint.register_blueprint(blueprint=xss_operation_blueprint, url_prefix='/xsss')

xss_analyzer_blueprint = Blueprint(name='xss_analyzer_blueprint', import_name=__name__)


@xss_analyzer_blueprint.route('/xss/<string:rule_name>', methods=['POST'])
def xss_analyzer_endpoint(rule_name: str):
    if response_elasticsearch.ping() is False:
        return {
            'type': 'xsss',
            'data': None,
            'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
        }, 500
    xss = response_elasticsearch.search(index='analyzer-xsss', query={'match_phrase': {'rule_name': rule_name}}, size=ES_MAX_RESULT)
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
        rule_libraries = response_elasticsearch.search(index='analyzer-rules', query={'match_phrase': {'rule_type': rule_library}}, size=ES_MAX_RESULT)
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
                            'type': 'xss_analyzer',
                            'data': None,
                            'reason': 'InternalServerError: Action found but can\'t load, abort error'
                        }, 500
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
                    }, default_body=result) is False:
                        error_logs.append({
                            'message': 'Action perform fail with some reasons',
                            'pattern': action['_source']['action_configuration']
                        })
            return {
                'type': 'xss_analyzer',
                'data': result,
                'reason': 'Success: Potential Cross Site Scripting detected'
            } if result is not None else {
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
                                'type': 'xss_analyzer',
                                'data': None,
                                'reason': 'InternalServerError: Action found but can\'t load, abort error'
                            }, 500
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
                        }, default_body=result) is False:
                            error_logs.append({
                                'message': 'Action perform fail with some reasons',
                                'pattern': action.raw['_source']['action_configuration']
                            })
                return {
                    'type': 'xss_analyzer',
                    'data': result,
                    'reason': 'Success: Potential Cross Site Scripting detected'
                } if result is not None else {
                    'type': 'xss_analyzer',
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
                                    'type': 'xss_analyzer',
                                    'data': None,
                                    'reason': 'InternalServerError: Action found but can\'t load, abort error'
                                }, 500
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
                            }, default_body=result) is False:
                                error_logs.append({
                                    'message': 'Action perform fail with some reasons',
                                    'pattern': action[3]
                                })
                        return {
                            'type': 'xss_analyzer',
                            'data': result,
                            'reason': 'Success: Potential Cross Site Scripting Injection detected'
                        }
                else:
                    error_logs.append({
                        'message': 'Target Field is not exist',
                        'pattern': f'{path}'
                    })
            return {
                'type': 'xss_analyzer',
                'data': None,
                'reason': 'Success: Clean log'
            }
        else:
            error_logs.append({
                'message': 'Target Field is invalid format',
                'pattern': f'{target_field}'
            })
    return {
        'type': 'xss_analyzer',
        'data': None,
        'reason': 'Success'
    }