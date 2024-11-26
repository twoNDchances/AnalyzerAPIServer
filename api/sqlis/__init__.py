from flask import Blueprint, request
from json import loads, dumps
from datetime import datetime
from .operations import sqli_operation_blueprint
from ..storage import response_elasticsearch, ES_MAX_RESULT
from ..functions import get_value_from_json, parse_path, is_valid_regex, re, traverse_json, execute_action, check_threshold


sqli_main_blueprint = Blueprint(name='sqli_main_blueprint', import_name=__name__)

sqli_main_blueprint.register_blueprint(blueprint=sqli_operation_blueprint, url_prefix='/sqlis')

sqli_analyzer_blueprint = Blueprint(name='sqli_analyzer_blueprint', import_name=__name__)


@sqli_analyzer_blueprint.route('/sqlis/<string:rule_name>', methods=['POST'])
def sqli_analyzer_endpoint(rule_name: str):
    if response_elasticsearch.ping() is False:
        return {
            'type': 'xsss',
            'data': None,
            'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
        }, 500
    sqli = response_elasticsearch.search(index='analyzer-sqlis', query={'term': {'rule_name.keyword': rule_name}}, size=ES_MAX_RESULT)
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
    analyzer_result = response_elasticsearch.search(index='analyzer-results', query={'bool': {
        'must': [
            {'term': {
                'reference.keyword': sqli_analyzer['_source']['rule_name']
            }},
            {'term': {
                'analyzer.keyword': 'SQLIs'
            }}
        ]
    }}, size=ES_MAX_RESULT).raw['hits']['hits']
    try:
        loads(request.data)
    except:
        return {
            'type': 'sqli_analyzer',
            'data': None,
            'reason': 'BadRequest: Body must be JSON'
        }, 400
    target_field = sqli_analyzer['_source']['target_field']
    ip_root_cause_field = sqli_analyzer['_source']['ip_root_cause_field']
    regex_matcher = sqli_analyzer['_source']['regex_matcher']
    rule_library = sqli_analyzer['_source']['rule_library']
    action_id = sqli_analyzer['_source']['action_id']
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
        rule_libraries = response_elasticsearch.search(index='analyzer-rules', query={'term': {'rule_type.keyword': rule_library}}, size=ES_MAX_RESULT)
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
                    for rule in rules:
                        if rule.search(str(value)):
                            result = {
                                '_message_': f'Detected from {rule_name} analyzer',
                                'field_name': key,
                                'field_value': value,
                                'by_rule': str(rule),
                                '_ip_root_cause_': ip_root_cause_field_value
                            }
                            flag = True
                            break
                    if flag:
                        break
                if flag:
                    break
            if result is not None:
                response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                    'match_count': analyzer_result[0]['_source']['match_count'] + 1,
                    'logs': dumps(logs)
                }, retry_on_conflict=ES_MAX_RESULT)
                if action_id is not None:
                    try:
                        action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
                    except:
                        return {
                            'type': 'sqli_analyzer',
                            'data': None,
                            'reason': 'InternalServerError: Action found but can\'t load, abort error'
                        }, 500
                    timestamp = datetime.now().timestamp()
                    action_timestamp = response_elasticsearch.index(index='analyzer-action-timestamps', document={
                        "analyzer": 'SQLIs',
                        "rule_name": rule_name,
                        "action_name": action.raw['_source']['action_name'],
                        "timestamp": int(timestamp)
                    })
                    if check_threshold(analyzer='SQLIs', rule_name=rule_name, action_name=action.raw['_source']['action_name'], action_configuration=loads(action.raw['_source']['action_configuration']), action_timestamp_id=action_timestamp['_id']) is True:
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
                        }, default_body=result, ip_root_cause=ip_root_cause_field_value) is False:
                            logs['[Error]'].append({
                                'Actions': {
                                    'message': 'Action perform fail with some reasons',
                                    'pattern': action['_source']['action_configuration']
                                }
                            })
                            response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                                'logs': dumps(logs)
                            }, retry_on_conflict=ES_MAX_RESULT)
                        else:
                            response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                                'execution_count': analyzer_result[0]['_source']['execution_count'] + 1
                            }, retry_on_conflict=ES_MAX_RESULT)
                return {
                    'type': 'sqli_analyzer',
                    'data': result,
                    'reason': 'Success: Potential SQL Injection detected'
                }
            return {
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
                            '_message_': f'Detected from {rule_name} analyzer',
                            'field_name': target_field,
                            'field_value': json_value_str,
                            'by_rule': str(rule),
                            '_ip_root_cause_': ip_root_cause_field_value
                        }
                        break
                if result is not None:
                    response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                        'match_count': analyzer_result[0]['_source']['match_count'] + 1,
                        'logs': dumps(logs)
                    }, retry_on_conflict=ES_MAX_RESULT)
                    if action_id is not None:
                        try:
                            action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
                        except:
                            return {
                                'type': 'sqli_analyzer',
                                'data': None,
                                'reason': 'InternalServerError: Action found but can\'t load, abort error'
                            }, 500
                        timestamp = datetime.now().timestamp()
                        action_timestamp = response_elasticsearch.index(index='analyzer-action-timestamps', document={
                            "analyzer": 'SQLIs',
                            "rule_name": rule_name,
                            "action_name": action.raw['_source']['action_name'],
                            "timestamp": int(timestamp)
                        })
                        if check_threshold(analyzer='SQLIs', rule_name=rule_name, action_name=action.raw['_source']['action_name'], action_configuration=loads(action.raw['_source']['action_configuration']), action_timestamp_id=action_timestamp['_id']) is True:
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
                            }, default_body=result, ip_root_cause=ip_root_cause_field_value) is False:
                                logs['[Error]'].append({
                                    'Actions': {
                                        'message': 'Action perform fail with some reasons',
                                        'pattern': action.raw['_source']['action_configuration']
                                    }
                                })
                                response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                                    'logs': dumps(logs)
                                }, retry_on_conflict=ES_MAX_RESULT)
                            else:
                                response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                                    'execution_count': analyzer_result[0]['_source']['execution_count'] + 1
                                }, retry_on_conflict=ES_MAX_RESULT)
                    return {
                        'type': 'sqli_analyzer',
                        'data': result,
                        'reason': 'Success: Potential SQL Injection detected'
                    }
                return {
                    'type': 'sqli_analyzer',
                    'data': None,
                    'reason': 'Success: Clean log'
                }
            else:
                logs['[Info]'].append({
                    'message': 'Target Field is not exist, skipped',
                    'pattern': f'{target_field}'
                })
                response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                    'logs': dumps(logs)
                }, retry_on_conflict=ES_MAX_RESULT)
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
                                '_message_': f'Detected from {rule_name} analyzer',
                                'field_name': path,
                                'field_value': json_value_str,
                                'by_rule': str(rule),
                                '_ip_root_cause_': ip_root_cause_field_value
                            }
                            break
                    if result is not None:
                        response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                            'match_count': analyzer_result[0]['_source']['match_count'] + 1,
                            'logs': dumps(logs)
                        }, retry_on_conflict=ES_MAX_RESULT)
                        if action_id is not None:
                            try:
                                action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
                            except:
                                return {
                                    'type': 'sqli_analyzer',
                                    'data': None,
                                    'reason': 'InternalServerError: Action found but can\'t load, abort error'
                                }, 500
                            timestamp = datetime.now().timestamp()
                            action_timestamp = response_elasticsearch.index(index='analyzer-action-timestamps', document={
                                "analyzer": 'SQLIs',
                                "rule_name": rule_name,
                                "action_name": action.raw['_source']['action_name'],
                                "timestamp": int(timestamp)
                            })
                            if check_threshold(analyzer='SQLIs', rule_name=rule_name, action_name=action.raw['_source']['action_name'], action_configuration=loads(action.raw['_source']['action_configuration']), action_timestamp_id=action_timestamp['_id']) is True:
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
                                }, default_body=result, ip_root_cause=ip_root_cause_field_value) is False:
                                    logs['[Error]'].append({
                                        'Actions': {
                                            'message': 'Action perform fail with some reasons',
                                            'pattern': action[3]
                                        }
                                    })
                                    response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                                        'logs': dumps(logs)
                                    }, retry_on_conflict=ES_MAX_RESULT)
                                else:
                                    response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                                        'execution_count': analyzer_result[0]['_source']['execution_count'] + 1
                                    }, retry_on_conflict=ES_MAX_RESULT)
                        return {
                            'type': 'sqli_analyzer',
                            'data': result,
                            'reason': 'Success: Potential SQL Injection detected'
                        }
                else:
                    logs['[Info]'].append({
                        'Analyzers': {
                            'message': 'Target Field is not exist, skipped',
                            'pattern': f'{path}'
                        }
                    })
                    response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                        'logs': dumps(logs)
                    }, retry_on_conflict=ES_MAX_RESULT)
            return {
                'type': 'sqli_analyzer',
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
            response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                'logs': dumps(logs)
            }, retry_on_conflict=ES_MAX_RESULT)
    return {
        'type': 'sqli_analyzer',
        'data': None,
        'reason': 'Success'
    }
