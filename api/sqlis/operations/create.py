from flask import request
from flask_restful import Resource
from json import loads
from ...storage import response_elasticsearch, ES_MAX_RESULT


class SQLInjectionRuleCreations(Resource):
    def post(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        try:
            loads(request.data)
        except:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        if (
            request_body.get('ruleName') and 
            request_body.get('isEnabled') and 
            request_body.get('targetField') and 
            request_body.get('ipRootCauseField') and 
            request_body.get('regexMatcher') and 
            request_body.get('ruleLibrary') and 
            request_body.get('wordlist') and 
            request_body.get('action')
        ) is None:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'BadRequest: Lack of requirement fields'
            }, 400
        if request_body['ruleName'].__len__() == 0 or request_body['ipRootCauseField'].__len__() == 0:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'NotAcceptable: Fill all of requirement fields'
            }, 406
        if request_body['isEnabled'] not in ['true', 'false']:
            return {
                'type': 'sqlis',
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
                'type': 'sqlis',
                'data': None,
                'reason': 'NotFound: Rule Library not found'
            }, 404
        wordlist = response_elasticsearch.search(
                index='analyzer-wordlists',
                body={
                    "aggs":{
                        "unique_names": {
                            "terms": {
                                "field": "wordlist_name.keyword"
                            }
                        }
                    },
                    "_source": False
                },
                size=ES_MAX_RESULT
            )
        wordlists = ['not_used']
        for wl in wordlist.raw['aggregations']['unique_names']['buckets']:
            wordlists.append(wl['key'])
        if request_body['wordlist'] not in wordlists:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'NotFound: Wordlist not found'
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
                'type': 'sqlis',
                'data': None,
                'reason': 'NotFound: Action not found'
            }, 404
        if request_body['regexMatcher'].__len__() == 0 and request_body['ruleLibrary'] == 'not_used':
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'NotAcceptable: Regex Matcher cannot be left blank if Rule Library is not used and vice versa'
            }, 406
        sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={"term": {"rule_name.keyword": request_body['ruleName']}}, size=ES_MAX_RESULT)
        if sqlis.raw['hits']['hits'].__len__() > 0:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'NotAcceptable: Rule Name is already exist'
            }, 406
        actions = response_elasticsearch.search(index='analyzer-actions', query={"term": {"action_name.keyword": request_body['action']}}, size=ES_MAX_RESULT)
        response_elasticsearch.index(index='analyzer-sqlis', document={
            'rule_name': request_body['ruleName'],
            'is_enabled': True if request_body['isEnabled'] == 'true' else False,
            'target_field': request_body['targetField'],
            'ip_root_cause_field': request_body['ipRootCauseField'],
            'regex_matcher': request_body['regexMatcher'],
            'rule_library': request_body['ruleLibrary'] if request_body['ruleLibrary'] != 'not_used' else None,
            'wordlist': request_body['wordlist'] if request_body['wordlist'] != 'not_used' else None,
            'action_id': actions.raw['hits']['hits'][0]['_id'] if actions.raw['hits']['hits'].__len__() == 1 else None,
            'type_attack': 'sqli'
        })
        return {
            'type': 'sqlis',
            'data': None,
            'reason': 'Success'
        }
