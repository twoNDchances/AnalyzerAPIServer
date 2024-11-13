from flask import request
from flask_restful import Resource
from json import loads
from ...storage import response_elasticsearch, ES_MAX_RESULT


class CrossSiteScriptingRuleModifications(Resource):
    def put(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if id is None:
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'BadRequest: ID required'
            }, 400
        try:
            xss = response_elasticsearch.get(index='analyzer-xsss', id=id)
        except:
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'NotFound: SQL Injection Rule is not found for update'
            }, 404
        try:
            loads(request.data)
        except:
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        if (request_body.get('ruleName') and request_body.get('isEnabled') and request_body.get('targetField') and request_body.get('ipRootCauseField') and request_body.get('regexMatcher') and request_body.get('ruleLibrary') and request_body.get('action')) is None:
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'BadRequest: Lack of requirement fields'
            }, 400
        if request_body['ruleName'].__len__() == 0 or request_body['ipRootCauseField'].__len__() == 0:
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'NotAcceptable: Fill all of requirement fields'
            }, 406
        if request_body['isEnabled'] not in ['true', 'false']:
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'NotAcceptable: Only \'true\' or \'false\' for Is Enabled'
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
                'type': 'xsss',
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
                'type': 'xsss',
                'data': None,
                'reason': 'NotFound: Action not found'
            }, 404
        if request_body['regexMatcher'].__len__() == 0 and request_body['ruleLibrary'] == 'not_used':
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'NotAcceptable: Regex Matcher cannot be left blank if Rule Library is not used and vice versa'
            }, 406
        old_rule_name = xss['_source']['rule_name']
        old_is_enabled = xss['_source']['is_enabled']
        old_target_field = xss['_source']['target_field']
        old_ip_root_cause_field = xss['_source']['ip_root_cause_field']
        old_regex_matcher = xss['_source']['regex_matcher']
        old_rule_library = xss['_source']['rule_library']
        old_action_id = xss['_source']['action_id']
        if old_rule_name != request_body.get('ruleName'):
            xsss = response_elasticsearch.search(index='analyzer-xsss', query={'match_phrase': {'rule_name': request_body['ruleName']}})
            if xsss.raw['hits']['hits'].__len__() > 0:
                return {
                    'type': 'xsss',
                    'data': None,
                    'reason': 'NotAcceptable: Rule Name is already exist'
                }, 406
            old_rule_name = request_body.get('ruleName')

        is_enabled = False
        if request_body.get('isEnabled') == 'true':
            is_enabled = True

        if old_is_enabled != is_enabled:
            old_is_enabled = is_enabled

        if old_target_field != request_body.get('targetField'):
            old_target_field = request_body.get('targetField')

        if old_ip_root_cause_field != request_body.get('ipRootCauseField'):
            old_ip_root_cause_field = request_body.get('ipRootCauseField')

        if old_regex_matcher != request_body.get('regexMatcher'):
            old_regex_matcher = request_body.get('regexMatcher')

        rule_library = None
        if request_body.get('ruleLibrary') != 'not_used':
            rule_library = request_body.get('ruleLibrary')

        if old_rule_library != rule_library:
            old_rule_library = rule_library

        action_id = None

        if request_body.get('action') != 'not_used':
            action_id = self.get_id_by_action_name(action_name=request_body.get('action'))

        if old_action_id != action_id:
            old_action_id = action_id
        response_elasticsearch.update(index='analyzer-xsss', id=id, doc={
            'rule_name': old_rule_name,
            'is_enabled': old_is_enabled,
            'target_field': old_target_field,
            'ip_root_cause_field': old_ip_root_cause_field,
            'regex_matcher': old_regex_matcher,
            'rule_library': old_rule_library,
            'action_id': old_action_id
        })
        return {
            'type': 'xsss',
            'data': {
                'id': id,
                'rule_name': old_rule_name,
                'is_enabled': old_is_enabled,
                'target_field': old_target_field,
                'ip_root_cause_field': old_ip_root_cause_field,
                'regex_matcher': 'Defined' if old_regex_matcher.__len__() != 0 else 'Undefined',
                'rule_library': old_rule_library if old_rule_library is not None else 'Not Used',
                'action': self.get_action_type_by_id(id=old_action_id) if old_action_id is not None else 'Inaction'
            },
            'reason': 'Success'
        }
    
    def get_id_by_action_name(self, action_name: str):
        action = response_elasticsearch.search(index='analyzer-actions', query={'match_phrase': {'action_name': action_name}}, size=ES_MAX_RESULT)
        return action.raw['hits']['hits'][0]['_id']
    
    def get_action_type_by_id(self, id: str):
        action_type = response_elasticsearch.get(index='analyzer-actions', id=id)
        return action_type.raw['_source']['action_type']
