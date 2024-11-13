from flask import Blueprint, request
from json import loads, dumps
import yara
from .operations import fus_operation_blueprint
from ..storage import response_elasticsearch, ES_MAX_RESULT
from ..functions import get_value_from_json, parse_path, is_valid_regex, re, traverse_json, execute_action, upload_to_virustotal, get_virustotal_report


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
    virus_total_api_key = fu_analyzer['_source']['virus_total_api_key']
    action_id = fu_analyzer['_source']['action_id']
    error_logs = []
    result = {
        'regex': {},
        'yara': {},
        'virus_total': {}
    }
    json = request.get_json()
    rules = []
    regex_detected = False
    yara_detected = False
    yaras = []
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
    if yara_rule_intergration is not False:
        yara_rules = response_elasticsearch.search(index='analyzer-yaras', query={'match_all': {}}, size=ES_MAX_RESULT)
        yara_rule_results = yara_rules.raw['hits']['hits']
        if yara_rule_results.__len__() > 0:
            for yara_rule_result in yara_rule_results:
                yaras.append(yara_rule_result['_source']['yara_rule'])
    json_value = get_value_from_json(data=json, path=target_field)
    if json_value is None:
        error_logs.append({
            'message': 'Target Field is not exist',
            'pattern': f'{target_field}'
        })
    else:
        json_value_str = str(json_value).encode().decode('unicode_escape')
        print(json_value_str)
        for rule in rules:
            if rule.search(json_value_str):
                result['regex'] = {
                    'message': f'Detected from {rule_name} analyzer',
                    'field_name': target_field,
                    'field_value': json_value_str,
                    'by_rule': str(rule),
                    'ip_root_cause': ip_root_cause_field_value
                }
                regex_detected = True
                break
        for each_yara in yaras:
            try:
                yara_compile = yara.compile(source=each_yara)
                yara_match = yara_compile.match(data=json_value_str)
                if yara_match.__len__() > 0:
                    result['yara'] = {
                        'message': f'Detected from {rule_name} analyzer',
                        'field_name': target_field,
                        'field_value': json_value_str,
                        'by_rule': str(each_yara),
                        'ip_root_cause': ip_root_cause_field_value
                    }
                    yara_detected = True
                    break
            except yara.Error as error:
                error_logs.append({
                    'message': f'YARA Rule can\'t work with some reason',
                    'pattern': each_yara,
                    'error': error
                })
                continue
        if regex_detected is False and yara_detected is False:
            text = dumps(json)
            if virus_total_api_key:
                scan_id = upload_to_virustotal(log_content=text, api_key=virus_total_api_key)
                if scan_id:
                    report = get_virustotal_report(scan_id=scan_id, api_key=virus_total_api_key)
                    if report:
                        stats = report["data"]["attributes"]["stats"]
                        if stats["malicious"] > 0 or stats["suspicious"] > 0:
                            virus_total_summary = {
                                'malicious': stats["malicious"],
                                'suspicious': stats["suspicious"],
                                'undetected': stats["undetected"],
                                'harmless': stats["harmless"],
                                'scan_results': [
                                    {
                                        'engine_name': result["engine_name"],
                                        'category': result["category"],
                                        'result': result["result"]
                                    }
                                    for result in report["data"]["attributes"]["results"].values()
                                    if result["category"] in ["malicious", "suspicious"]
                                ]
                            }
                            result['virus_total'] = virus_total_summary
            else:
                error_logs.append({
                    'message': 'This log passes Regex and YARA scan but can\'t perform scan with VirusTotal because API Key not specific',
                    'pattern': virus_total_api_key
                })
        if result['regex'] != {} or result['yara'] != {} or result['virus_total'] != {}:
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
                    'virus_total_api_key': fu_analyzer['_source']['virus_total_api_key'],
                    'action': action.raw['_source']['action_name'],
                    'result': result
                }, default_body=result) is False:
                    error_logs.append({
                        'message': 'Action perform fail with some reasons',
                        'pattern': action.raw['_source']['action_configuration']
                    })
            return {
                'type': 'fu_analyzer',
                'data': result,
                'reason': 'Success'
            }
        return {
            'type': 'fu_analyzer',
            'data': None,
            'reason': 'Success: Clean log'
        }
    return {
        'type': 'fu_analyzer',
        'data': None,
        'reason': 'Success'
    }
    # if target_field.__len__() == 0:
    #     if all_fields.__len__() > 0:
    #         flag = False
    #         for field in all_fields:
    #             for key, value in field.items():
    #                 for rule in rules:
    #                     if rule.search(str(value)):
    #                         result = {
    #                             'rule': {
    #                                 'message': f'Detected from {rule_name} analyzer',
    #                                 'field_name': key,
    #                                 'field_value': value,
    #                                 'by_rule': str(rule),
    #                                 'ip_root_cause': ip_root_cause_field_value
    #                             }
    #                         }
    #                         regex_detected = True
    #                         flag = True
    #                         break
    #                 if flag:
    #                     break
    #             if flag:
    #                 break
    #         if yaras.__len__() > 0:
    #             flag = False
    #             for field in all_fields:
    #                 for key, value in field.items():
    #                     for each_yara in yaras:
    #                         try:
    #                             yara_compile = yara.compile(source=each_yara)
    #                             yara_match = yara_compile.match(data=value)
    #                             if yara_match.__len__() > 0:
    #                                 result['yara'] = {
    #                                     'message': f'Detected from {rule_name} analyzer',
    #                                     'field_name': key,
    #                                     'field_value': value,
    #                                     'by_rule': str(each_yara),
    #                                     'ip_root_cause': ip_root_cause_field_value
    #                                 }
    #                                 yara_detected = True
    #                                 flag = True
    #                                 break
    #                         except:
    #                             error_logs.append({
    #                                 'message': f'YARA Rule can\'t work with some reason',
    #                                 'pattern': each_yara
    #                             })
    #                             continue
    #                     if flag:
    #                         break
    #                 if flag:
    #                     break
    #         if regex_detected is False and yara_detected:
                
    #         if result is not None:
    #             if action_id is not None:
    #                 try:
    #                     action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
    #                 except:
    #                     return {
    #                         'type': 'fu_analyzer',
    #                         'data': None,
    #                         'reason': 'InternalServerError: Action found but can\'t load, abort error'
    #                     }, 500
    #                 if execute_action(action_type=action.raw['_source']['action_type'], action_configuration=loads(action.raw['_source']['action_configuration']), virtual_variable_list={
    #                     'id': fu_analyzer['_id'],
    #                     'rule_name': fu_analyzer['_source']['rule_name'],
    #                     'is_enabled': fu_analyzer['_source']['is_enabled'],
    #                     'target_field': fu_analyzer['_source']['target_field'],
    #                     'target_value': all_fields,
    #                     'ip_root_cause_field': fu_analyzer['_source']['ip_root_cause_field'],
    #                     'ip_root_cause_value': ip_root_cause_field_value,
    #                     'regex_matcher': fu_analyzer['_source']['regex_matcher'],
    #                     'rule_library': fu_analyzer['_source']['rule_library'],
    #                     'action': action.raw['_source']['action_name'],
    #                     'result': result
    #                 }, default_body=result) is False:
    #                     error_logs.append({
    #                         'message': 'Action perform fail with some reasons',
    #                         'pattern': action['_source']['action_configuration']
    #                     })
    #         return {
    #             'type': 'fu_analyzer',
    #             'data': result,
    #             'reason': 'Success: Potential Cross Site Scripting detected'
    #         } if result is not None else {
    #             'type': 'fu_analyzer',
    #             'data': None,
    #             'reason': 'Success: Clean log'
    #         }
    #     else:
    #         return {
    #             'type': 'fu_analyzer',
    #             'data': None,
    #             'reason': 'Success: No log'
    #         }
    # else:
    #     target_field_path = parse_path(path=target_field)
    #     if str(type(target_field_path)) == "<class 'str'>":
    #         json_value = get_value_from_json(data=json, path=target_field)
    #         if json_value is not None:
    #             json_value_str = str(json_value)
    #             for rule in rules:
    #                 if rule.search(json_value_str):
    #                     result = {
    #                         'message': f'Detected from {rule_name} analyzer',
    #                         'field_name': target_field,
    #                         'field_value': json_value_str,
    #                         'by_rule': str(rule),
    #                         'ip_root_cause': ip_root_cause_field_value
    #                     }
    #                     regex_detected = True
    #                     break
    #             if yaras.__len__() > 0:
    #                 for each_yara in yaras:
    #                     try:
    #                         yara_compile = yara.compile(source=each_yara)
    #                         yara_match = yara_compile.match(data=json_value_str)
    #                         if yara_match.__len__() > 0:
    #                             result['yara'] = {
    #                                 'message': f'Detected from {rule_name} analyzer',
    #                                 'field_name': target_field,
    #                                 'field_value': json_value_str,
    #                                 'by_rule': str(each_yara),
    #                                 'ip_root_cause': ip_root_cause_field_value
    #                             }
    #                             yara_detected = True
    #                             break
    #                     except:
    #                         error_logs.append({
    #                             'message': f'YARA Rule can\'t work with some reason',
    #                             'pattern': each_yara
    #                         })
    #                         continue
    #             # if result is not None:
    #             #     if action_id is not None:
    #             #         try:
    #             #             action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
    #             #         except:
    #             #             return {
    #             #                 'type': 'fu_analyzer',
    #             #                 'data': None,
    #             #                 'reason': 'InternalServerError: Action found but can\'t load, abort error'
    #             #             }, 500
    #             #         if execute_action(action_type=action.raw['_source']['action_type'], action_configuration=loads(action.raw['_source']['action_configuration']), virtual_variable_list={
    #             #             'id': fu_analyzer['_id'],
    #             #             'rule_name': fu_analyzer['_source']['rule_name'],
    #             #             'is_enabled': fu_analyzer['_source']['is_enabled'],
    #             #             'target_field': fu_analyzer['_source']['target_field'],
    #             #             'target_value': json_value_str,
    #             #             'ip_root_cause_field': fu_analyzer['_source']['ip_root_cause_field'],
    #             #             'ip_root_cause_value': ip_root_cause_field_value,
    #             #             'regex_matcher': fu_analyzer['_source']['regex_matcher'],
    #             #             'rule_library': fu_analyzer['_source']['rule_library'],
    #             #             'action': action.raw['_source']['action_name'],
    #             #             'result': result
    #             #         }, default_body=result) is False:
    #             #             error_logs.append({
    #             #                 'message': 'Action perform fail with some reasons',
    #             #                 'pattern': action.raw['_source']['action_configuration']
    #             #             })
    #             return {
    #                 'type': 'fu_analyzer',
    #                 'data': result,
    #                 'reason': 'Success: Potential Cross Site Scripting detected'
    #             } if result is not None else {
    #                 'type': 'fu_analyzer',
    #                 'data': None,
    #                 'reason': 'Success: Clean log'
    #             }
    #         else:
    #             error_logs.append({
    #                 'message': 'Target Field is not exist',
    #                 'pattern': f'{target_field}'
    #             })
    #     elif str(type(target_field_path)) == "<class 'list'>":
    #         target_field_value = []
    #         for path in target_field_path:
    #             path_value = get_value_from_json(data=json, path=path)
    #             target_field_value.append({
    #                 path: path_value
    #             })
    #         for path in target_field_path:
    #             json_value = get_value_from_json(data=json, path=path)
    #             if json_value is not None:
    #                 json_value_str = str(json_value)
    #                 for rule in rules:
    #                     if rule.search(json_value_str):
    #                         result = {
    #                             'message': f'Detected from {rule_name} analyzer',
    #                             'field_name': path,
    #                             'field_value': json_value_str,
    #                             'by_rule': str(rule),
    #                             'ip_root_cause': ip_root_cause_field_value
    #                         }
    #                         regex_detected = True
    #                         break
    #                 if yaras.__len__() > 0:
    #                     for each_yara in yaras:
    #                         try:
    #                             yara_compile = yara.compile(source=each_yara)
    #                             yara_match = yara_compile.match(data=json_value_str)
    #                             if yara_match.__len__() > 0:
    #                                 result['yara'] = {
    #                                     'message': f'Detected from {rule_name} analyzer',
    #                                     'field_name': target_field,
    #                                     'field_value': json_value_str,
    #                                     'by_rule': str(each_yara),
    #                                     'ip_root_cause': ip_root_cause_field_value
    #                                 }
    #                                 yara_detected = True
    #                                 break
    #                         except:
    #                             error_logs.append({
    #                                 'message': f'YARA Rule can\'t work with some reason',
    #                                 'pattern': each_yara
    #                             })
    #                             continue
    #                 if result is not None:
    #                     if action_id is not None:
    #                         try:
    #                             action = response_elasticsearch.get(index='analyzer-actions', id=action_id)
    #                         except:
    #                             return {
    #                                 'type': 'fu_analyzer',
    #                                 'data': None,
    #                                 'reason': 'InternalServerError: Action found but can\'t load, abort error'
    #                             }, 500
    #                         if execute_action(action_type=action.raw['_source']['action_type'], action_configuration=loads(action.raw['_source']['action_configuration']), virtual_variable_list={
    #                             'id': fu_analyzer['_id'],
    #                             'rule_name': fu_analyzer['_source']['rule_name'],
    #                             'is_enabled': fu_analyzer['_source']['is_enabled'],
    #                             'target_field': fu_analyzer['_source']['target_field'],
    #                             'target_value': target_field_value,
    #                             'ip_root_cause_field': fu_analyzer['_source']['ip_root_cause_field'],
    #                             'ip_root_cause_value': ip_root_cause_field_value,
    #                             'regex_matcher': fu_analyzer['_source']['regex_matcher'],
    #                             'rule_library': fu_analyzer['_source']['rule_library'],
    #                             'action': action.raw['_source']['action_name'],
    #                             'result': result
    #                         }, default_body=result) is False:
    #                             error_logs.append({
    #                                 'message': 'Action perform fail with some reasons',
    #                                 'pattern': action[3]
    #                             })
    #                     return {
    #                         'type': 'fu_analyzer',
    #                         'data': result,
    #                         'reason': 'Success: Potential Cross Site Scripting Injection detected'
    #                     }
    #             else:
    #                 error_logs.append({
    #                     'message': 'Target Field is not exist',
    #                     'pattern': f'{path}'
    #                 })
    #         return {
    #             'type': 'fu_analyzer',
    #             'data': None,
    #             'reason': 'Success: Clean log'
    #         }
    #     else:
    #         error_logs.append({
    #             'message': 'Target Field is invalid format',
    #             'pattern': f'{target_field}'
    #         })
    # return {
    #     'type': 'fu_analyzer',
    #     'data': None,
    #     'reason': 'Success'
    # }