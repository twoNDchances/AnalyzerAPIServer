from flask import Blueprint, request
from json import loads, dumps
import yara
from .operations import fus_operation_blueprint
from ..storage import response_elasticsearch, ES_MAX_RESULT
from ..functions import get_value_from_json, parse_path, is_valid_regex, re, execute_action


fus_main_blueprint = Blueprint(name='fus_main_blueprint', import_name=__name__)

fus_main_blueprint.register_blueprint(blueprint=fus_operation_blueprint, url_prefix='/fus')

fus_analyzer_blueprint = Blueprint(name='fus_analyzer_blueprint', import_name=__name__)

@fus_analyzer_blueprint.route(rule='/fus/<string:rule_name>', methods=['POST'])
def fus_analyzer_page(rule_name: str):
    if response_elasticsearch.ping() is False:
        return {
            'type': 'fus',
            'data': None,
            'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
        }, 500
    fu = response_elasticsearch.search(index='analyzer-fus', query={'match_phrase': {'rule_name': rule_name}}, size=ES_MAX_RESULT)
    fu_result = fu.raw['hits']['hits']
    if fu_result.__len__() == 0:
        return {
            'type': 'fus',
            'data': None,
            'reason': 'NotFound: Rule Name not found'
        }, 404
    fu_analyzer = fu_result[0]
    if fu_analyzer['_source']['is_enabled'] is False:
        return {
            'type': 'fu_analyzer',
            'data': None,
            'reason': 'Success: This analyzer is disabled'
        }
    analyzer_result = response_elasticsearch.search(index='analyzer-results', query={'bool': {
        'must': {
            'match_phrase': {
                'reference': fu_analyzer['_source']['rule_name']
            },
            'match_phrase': {
                'analyzer': 'FUs'
            }
        }
    }}, size=ES_MAX_RESULT).raw['hits']['hits']
    print(analyzer_result)
    try:
        loads(request.data)
    except:
        return {
            'type': 'fu_analyzer',
            'data': None,
            'reason': 'BadRequest: Body must be JSON'
        }, 400
    target_field = fu_analyzer['_source']['target_field']
    ip_root_cause_field = fu_analyzer['_source']['ip_root_cause_field']
    regex_matcher = fu_analyzer['_source']['regex_matcher']
    rule_library = fu_analyzer['_source']['rule_library']
    yara_rule_intergration = fu_analyzer['_source']['yara_rule_intergration']
    action_id = fu_analyzer['_source']['action_id']
    logs = {
        '[Warning]': [],
        '[Error]': [],
        '[Info]': []
    }
    result = {
        'regex': None,
        'yara': None
    }
    json = request.get_json()
    rules = []
    yaras = []
    ip_root_cause_field_value = '<>'
    ip_root_cause_field_validation = parse_path(path=ip_root_cause_field)
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
    if yara_rule_intergration is not False:
        yara_rules = response_elasticsearch.search(index='analyzer-yaras', query={'match_all': {}}, size=ES_MAX_RESULT)
        yara_rule_results = yara_rules.raw['hits']['hits']
        if yara_rule_results.__len__() > 0:
            for yara_rule_result in yara_rule_results:
                yaras.append(yara_rule_result['_source']['yara_rule'])
    json_value = get_value_from_json(data=json, path=target_field)
    if json_value is None:
        logs['[Info]'].append({
            'Analyzers': {
                'message': 'Target Field is not exist, skipped',
                'pattern': f'{target_field}'
            }
        })
        response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
            'logs': dumps(logs)
        })
    else:
        json_value_str = str(json_value)
        for rule in rules:
            if rule.search(json_value_str):
                result['regex'] = {
                    '_message_': f'Detected from {rule_name} analyzer',
                    'field_name': target_field,
                    'field_value': json_value_str,
                    'by_rule': str(rule),
                    '_ip_root_cause_': ip_root_cause_field_value
                }
                break
        for each_yara in yaras:
            try:
                yara_compile = yara.compile(source=each_yara)
                yara_match = yara_compile.match(data=json_value_str.encode().decode('unicode_escape').encode('latin-1'))
                if yara_match.__len__() > 0:
                    result['yara'] = {
                        '_message_': f'Detected from {rule_name} analyzer',
                        'field_name': target_field,
                        'field_value': json_value_str,
                        'by_rule': str(each_yara),
                        '_ip_root_cause_': ip_root_cause_field_value
                    }
                    break
            except yara.Error as error:
                logs['[Error]'].append({
                    'Intergrations': {
                        'message': error,
                        'pattern': each_yara,
                    }
                })
                continue
        if result['regex'] is not None or result['yara'] is not None:
            response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                'match_count': analyzer_result[0]['_source']['match_count'] + 1,
                'logs': dumps(logs)
            })
            if action_id is not None:
                try:
                    action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
                except:
                    return {
                        'type': 'fu_analyzer',
                        'data': None,
                        'reason': 'InternalServerError: Action found but can\'t load, abort error'
                    }, 500
                if execute_action(action_type=action.raw['_source']['action_type'], action_configuration=loads(action.raw['_source']['action_configuration']), virtual_variable_list={
                    'id': fu_analyzer['_id'],
                    'rule_name': fu_analyzer['_source']['rule_name'],
                    'is_enabled': fu_analyzer['_source']['is_enabled'],
                    'target_field': fu_analyzer['_source']['target_field'],
                    'target_value': json_value_str,
                    'ip_root_cause_field': fu_analyzer['_source']['ip_root_cause_field'],
                    'ip_root_cause_value': ip_root_cause_field_value,
                    'regex_matcher': fu_analyzer['_source']['regex_matcher'],
                    'rule_library': fu_analyzer['_source']['rule_library'],
                    'yara_rule_intergration': fu_analyzer['_source']['yara_rule_intergration'],
                    'action': action.raw['_source']['action_name'],
                    'result': result
                }, default_body=result) is False:
                    logs['[Error]'].append({
                        'Actions': {
                            'message': 'Action perform fail with some reasons',
                            'pattern': action.raw['_source']['action_configuration']
                        }
                    })
                    response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                        'logs': dumps(logs)
                    })
                else:
                    response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
                        'execution_count': analyzer_result[0]['_source']['execution_count'] + 1
                    })
            return {
                'type': 'fu_analyzer',
                'data': result,
                'reason': 'Success'
            }
        response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
            'logs': dumps(logs)
        })
        return {
            'type': 'fu_analyzer',
            'data': None,
            'reason': 'Success: Clean log'
        }
    response_elasticsearch.update(index='analyzer-results', id=analyzer_result[0]['_id'], doc={
        'logs': dumps(logs)
    })
    return {
        'type': 'fu_analyzer',
        'data': None,
        'reason': 'Success'
    }
