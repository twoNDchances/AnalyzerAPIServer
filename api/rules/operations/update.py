from flask import request
from flask_restful import Resource
from json import loads
from ...storage import response_elasticsearch, ES_MAX_RESULT


class RuleModifications(Resource):
    def get(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not id:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'BadRequest: ID is required'
            }, 400
        try:
            rule = response_elasticsearch.get(index='analyzer-rules', id=id).raw
        except:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'NotFound'
            }, 404
        sqli_related_list = []
        sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={'term': {'rule_library.keyword': rule['_source']['rule_type']}}, size=ES_MAX_RESULT)
        sqli_results = sqlis.raw['hits']['hits']
        if sqli_results.__len__() > 0:
            for sqli_result in sqli_results:
                sqli_related_list.append(sqli_result['_source']['rule_name'])
        xss_related_list = []
        xsss = response_elasticsearch.search(index='analyzer-xsss', query={'term': {'rule_library.keyword': rule['_source']['rule_type']}}, size=ES_MAX_RESULT)
        xss_results = xsss.raw['hits']['hits']
        if xss_results.__len__() > 0:
            for xss_result in xss_results:
                xss_related_list.append(xss_result['_source']['rule_name'])
        fu_related_list = []
        fus = response_elasticsearch.search(index='analyzer-fus', query={'term': {'rule_library.keyword': rule['_source']['rule_type']}}, size=ES_MAX_RESULT)
        fu_results = fus.raw['hits']['hits']
        if fu_results.__len__() > 0:
            for fu_result in fu_results:
                fu_related_list.append(fu_result['_source']['rule_name'])
        return {
            'type': 'rules',
            'data': {
                'sqli': sqli_related_list,
                'xss': xss_related_list,
                'fu': fu_related_list
            },
            'reason': 'Success'
        }


    def put(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not id:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'BadRequest: ID is required'
            }, 400
        try:
            forbidden_list = ['SQLI', 'XSS', 'FU']
            rule = response_elasticsearch.get(index='analyzer-rules', id=id)
            if rule.raw['_source']['rule_type'] in forbidden_list:
                return {
                    'type': 'rules',
                    'data': None,
                    'reason': 'Forbidden: Rule Library default can\'t update'
                }, 403
        except:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'NotFound'
            }, 404
        try:
            loads(request.data)
        except:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        if (request_body.get('ruleType') and request_body.get('ruleExecution') and request_body.get('ruleDescription')) is None:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'BadRequest: Lack of requirement fields'
            }, 400
        new_rule_type = request_body.get('ruleType')
        new_rule_execution = request_body.get('ruleExecution')
        new_rule_description = request_body.get('ruleDescription')
        if new_rule_type != rule.raw['_source']['rule_type']:
            rules = response_elasticsearch.search(index='analyzer-rules', query={'term': {'rule_type.keyword': new_rule_type}}, size=ES_MAX_RESULT).raw
            if rules['hits']['hits'].__len__() > 0:
                return {
                    'type': 'rules',
                    'data': None,
                    'reason': 'NotAcceptable: Rule Type is exist'
                }, 406
        if new_rule_type != rule.raw['_source']['rule_type'] or new_rule_execution != rule.raw['_source']['rule_execution'] or new_rule_description != rule.raw['_source']['rule_description']:
            response_elasticsearch.update(index='analyzer-rules', id=rule.raw['_id'], doc={
                'rule_type': new_rule_type,
                'rule_execution': new_rule_execution,
                'rule_description': new_rule_description
            })
        return {
            'type': 'rules',
            'data': {
                'id': rule.raw['_id'],
                'rule_type': new_rule_type,
                'rule_execution': new_rule_execution,
                'rule_description': new_rule_description
            },
            'reason': 'Success'
        }