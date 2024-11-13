from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class CrossSiteScriptingRuleLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if response_elasticsearch.count(index='analyzer-xsss').raw['count'] == 0:
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'NotFound: Not found any record in XSSs'
            }, 404
        xsss = response_elasticsearch.search(index='analyzer-xsss', query={"match_all": {}}, size=ES_MAX_RESULT)
        return {
            'type': 'xsss',
            'data': [{
                'id': xss['_id'],
                'rule_name': xss['_source']['rule_name'],
                'is_enabled': xss['_source']['is_enabled'],
                'target_field': xss['_source']['target_field'],
                'ip_root_cause_field': xss['_source']['ip_root_cause_field'],
                'regex_matcher': 'Defined' if xss['_source']['regex_matcher'].__len__() > 0 else 'Undefined',
                'rule_library': xss['_source']['rule_library'] if xss['_source']['rule_library'] is not None else 'Not Used',
                'action_id': self.get_action_type_by_id(id=xss['_source']['action_id']) if xss['_source']['action_id'] is not None else 'Inaction'
            } for xss in xsss.raw['hits']['hits']],
            'reason': 'Success'
        }

    def get_action_type_by_id(self, id: str):
        action_type = response_elasticsearch.get(index='analyzer-actions', id=id)
        return action_type.raw['_source']['action_type']
