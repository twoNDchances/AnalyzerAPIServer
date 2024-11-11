from flask import jsonify
from flask_restful import Resource
from ...storage import response_elasticsearch


class SQLInjectionRuleLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if response_elasticsearch.count(index='analyzer-sqlis').raw['count'] == 0:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'NotFound: Not found any record in SQLIs'
            }, 404
        sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={"match_all": {}}, size=1000000000)
        return {
            'type': 'sqlis',
            'data': [{
                'id': sqli['_id'],
                'rule_name': sqli['_source']['rule_name'],
                'is_enabled': sqli['_source']['is_enabled'],
                'target_field': sqli['_source']['target_field'],
                'ip_root_cause_field': sqli['_source']['ip_root_cause_field'],
                'regex_matcher': 'Defined' if sqli['_source']['regex_matcher'].__len__() > 0 else 'Undefined',
                'rule_library': sqli['_source']['rule_library'] if sqli['_source']['rule_library'] is not None else 'Not Used',
                'action_id': self.get_action_type_by_id(id=sqli['_source']['action_id']) if sqli['_source']['action_id'] is not None else 'Inaction'
            } for sqli in sqlis.raw['hits']['hits']],
            'reason': 'Success'
        }

    def get_action_type_by_id(self, id: str):
        action_type = response_elasticsearch.get(index='analyzer-actions', id=id)
        return action_type.raw['_source']['action_type']

