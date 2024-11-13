from flask import request
from flask_restful import Resource
from json import loads
from ...storage import response_elasticsearch, ES_MAX_RESULT
from ...functions import parse_path


class FileUploadRuleCreations(Resource):
    def post(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        try:
            loads(request.data)
        except:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        if (request_body.get('ruleName') and request_body.get('isEnabled') and request_body.get('targetField') and request_body.get('ipRootCauseField') and request_body.get('regexMatcher') and request_body.get('ruleLibrary') and request_body.get('virusTotalAPIKey') and request_body.get('action')) is None:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'BadRequest: Lack of requirement fields'
            }, 400
        if request_body['ruleName'].__len__() == 0 or request_body['ipRootCauseField'].__len__() == 0:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'NotAcceptable: Fill all of requirement fields'
            }, 406
        if request_body['isEnabled'] not in ['true', 'false']:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'NotAcceptable: Only \'true\' or \'false\' for Is Enabled'
            }, 406
        if request_body['targetField'].__len__() == 0:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'BadRequest: Target Field is required'
            }, 400
        if not isinstance(parse_path(path=request_body['targetField']), str):
            return {
                'type': 'fus',
                'data': None,
                'reason': 'NotAcceptable: Target Field must be string, not accept list syntax'
            }, 406
        rule_types = response_elasticsearch.search(
                index='analyzer-rules',
                body={
                    "aggs":{
                        "unique_names": {
                            "terms": {
                                "field": "rule_type.keyword"
                            }
                        }
                    },
                    "_source": False
                },
                size=ES_MAX_RESULT
            )
        rule_type_list = ['not_used']
        for rule_type in rule_types.raw['aggregations']['unique_names']['buckets']:
            rule_type_list.append(rule_type['key'])
        if request_body['ruleLibrary'] not in rule_type_list:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'NotFound: Rule Library not found'
            }, 404
        action_names = response_elasticsearch.search(
                index='analyzer-actions',
                body={
                    "aggs":{
                        "unique_names": {
                            "terms": {
                                "field": "action_name.keyword"
                            }
                        }
                    },
                    "_source": False
                },
                size=ES_MAX_RESULT
            )
        action_name_list = ['not_used']
        for action_name in action_names.raw['aggregations']['unique_names']['buckets']:
            action_name_list.append(action_name['key'])
        if request_body['action'] not in action_name_list:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'NotFound: Action not found'
            }, 404
        if request_body['regexMatcher'].__len__() == 0 and request_body['ruleLibrary'] == 'not_used':
            return {
                'type': 'fus',
                'data': None,
                'reason': 'NotAcceptable: Regex Matcher cannot be left blank if Rule Library is not used and vice versa'
            }, 406
        fus = response_elasticsearch.search(index='analyzer-fus', query={"match_phrase": {"rule_name": request_body['ruleName']}}, size=ES_MAX_RESULT)
        if fus.raw['hits']['hits'].__len__() > 0:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'NotAcceptable: Rule Name is already exist'
            }, 406
        actions = response_elasticsearch.search(index='analyzer-actions', query={"match_phrase": {"action_name": request_body['action']}}, size=ES_MAX_RESULT)
        response_elasticsearch.index(index='analyzer-fus', document={
            'rule_name': request_body['ruleName'],
            'is_enabled': True if request_body['isEnabled'] == 'true' else False,
            'target_field': request_body['targetField'],
            'ip_root_cause_field': request_body['ipRootCauseField'],
            'regex_matcher': request_body['regexMatcher'],
            'rule_library': request_body['ruleLibrary'] if request_body['ruleLibrary'] != 'not_used' else None,
            'yara_rule_intergration': True if request_body.get('yaraRuleIntergration') is not None else False,
            'virus_total_api_key': request_body['virusTotalAPIKey'] if request_body['virusTotalAPIKey'].__len__() > 0 else None,
            'action_id': actions.raw['hits']['hits'][0]['_id'] if actions.raw['hits']['hits'].__len__() == 1 else None,
            'type_attack': 'fu'
        })
        response_elasticsearch.index(index='analyzer-results', document={
            'analyzer': 'FUs',
            'reference': request_body['ruleName'],
            'log': '{}'
        })
        return {
            'type': 'sqlis',
            'data': None,
            'reason': 'Success'
        }
