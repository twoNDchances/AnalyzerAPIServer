from flask import request
from flask_restful import Resource
from json import loads
from ...storage import response_elasticsearch


class RuleInheritances(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if response_elasticsearch.count(index='analyzer-rules').raw['count'] == 0:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'NotFound: Not found any record in Rules'
            }, 404
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
            }, size=1000000000
        )
        return {
            'type': 'rules',
            'data': [rule_type['key'] for rule_type in rule_types.raw['aggregations']['unique_names']['buckets']],
            'reason': 'Success'
        }
    
    def post(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        try:
            loads(request.data)
        except:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        rule_type = request_body.get('ruleType')
        rule_library = request_body.get('ruleLibrary')
        rule_execution = request_body.get('ruleExecution')
        rule_description = request_body.get('ruleDescription')
        if not rule_type:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'BadRequest: Rule Type is required'
            }, 400
        if not rule_execution:
            return {
                'type': 'rule',
                'data': None,
                'reason': 'BadRequest: Rule Execution is required'
            }, 400
        if not rule_description:
            return {
                'type': 'rule',
                'data': None,
                'reason': 'BadRequest: Rule Description is required'
            }, 400
        rules = response_elasticsearch.search(index='analyzer-rules', body={"query": {"match_all": {}}}, size=1000000000)
        for rule in rules.raw['hits']['hits']:
            if rule['_source']['rule_type'] == rule_type:
                return {
                'type': 'rules',
                'data': None,
                'reason': 'NotAcceptable: Rule Type is exist'
            }, 406
        rule_holder = []
        if rule_library:
            if isinstance(rule_library, str):
                rule_holder = [(rule['_source']['rule_execution'], rule['_source']['rule_description']) for rule in rules.raw['hits']['hits'] if rule['_source']['rule_type'] == rule_library]
            if isinstance(rule_library, list):
                for each_rule in rule_library:
                    rule_holder = rule_holder + [(rule['_source']['rule_execution'], rule['_source']['rule_description']) for rule in rules.raw['hits']['hits'] if rule['_source']['rule_type'] == each_rule]
        if isinstance(rule_execution, str) and isinstance(rule_description, str):
            if rule_execution.__len__() == 0 or rule_description.__len__() == 0:
                return {
                    'type': 'rules',
                    'data': None,
                    'reason': 'NotAcceptable: Both Rule Execution and Rule Description is required'
                }, 406
            response_elasticsearch.index(index='analyzer-rules', document={
                'rule_type': rule_type,
                'rule_execution': rule_execution,
                'rule_description': rule_description
            })
        else:
            if isinstance(rule_execution, list) and isinstance(rule_description, list):
                for rule_exec, rule_descr in zip(rule_execution, rule_description):
                    if rule_exec.__len__() == 0 or rule_descr.__len__() == 0:
                        return {
                            'type': 'rules',
                            'data': None,
                            'reason': 'NotAcceptable: Both Rule Execution and Rule Description is required'
                        }, 406
                    response_elasticsearch.index(index='analyzer-rules', document={
                        'rule_type': rule_type,
                        'rule_execution': rule_exec,
                        'rule_description': rule_descr
                    })
            else:
                return {
                    'type': 'rules',
                    'data': None,
                    'reason': 'NotAcceptable: Both Rule Execution and Rule Description is required'
                }, 406
        for rule_hold in rule_holder:
            response_elasticsearch.index(index='analyzer-rules', document={
                'rule_type': rule_type,
                'rule_execution': rule_hold[0],
                'rule_description': rule_hold[1]
            })
        return {
            'type': 'rules',
            'data': None,
            'reason': 'Success'
        }