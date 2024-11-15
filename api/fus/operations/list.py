from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class FileUploadRuleLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if response_elasticsearch.count(index='analyzer-fus').raw['count'] == 0:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'NotFound: Not found any record in fus'
            }, 404
        fus = response_elasticsearch.search(index='analyzer-fus', query={"match_all": {}}, size=ES_MAX_RESULT)
        return {
            'type': 'fus',
            'data': [{
                'id': fu['_id'],
                'rule_name': fu['_source']['rule_name'],
                'is_enabled': fu['_source']['is_enabled'],
                'target_field': fu['_source']['target_field'],
                'ip_root_cause_field': fu['_source']['ip_root_cause_field'],
                'regex_matcher': 'Defined' if fu['_source']['regex_matcher'].__len__() > 0 else 'Undefined',
                'rule_library': fu['_source']['rule_library'] if fu['_source']['rule_library'] is not None else 'Not Used',
                'yara_rule_intergration': 'Yes' if fu['_source']['yara_rule_intergration'] is True else 'No',
                'action_id': self.get_action_type_by_id(id=fu['_source']['action_id']) if fu['_source']['action_id'] is not None else 'Inaction'
            } for fu in fus.raw['hits']['hits']],
            'reason': 'Success'
        }

    def get_action_type_by_id(self, id: str):
        action_type = response_elasticsearch.get(index='analyzer-actions', id=id)
        return action_type.raw['_source']['action_type']

