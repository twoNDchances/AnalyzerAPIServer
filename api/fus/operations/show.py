from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class FileUploadRuleDetails(Resource):
    def get(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if id is None:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'BadRequest: ID required'
            }, 400
        try:
            fu = response_elasticsearch.get(index='analyzer-fus', id=id).raw
        except:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'NotFound: File Upload Rule is not found for show'
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
                    },
                    size=ES_MAX_RESULT
                )
        choice_rules = {
            'choice': 'not_used' if fu['_source']['rule_library'] is None else fu['_source']['rule_library'],
            'rules': [rule_type['key'] for rule_type in rule_types.raw['aggregations']['unique_names']['buckets']]
        }
        actions = response_elasticsearch.search(index='analyzer-actions', query={'match_all': {}}, size=ES_MAX_RESULT)
        choice_actions = {
            'choice': 'not_used' if fu['_source']['action_id'] is None else self.get_action_name_by_id(id=fu['_source']['action_id']),
            'actions': [action['_source']['action_name'] for action in actions.raw['hits']['hits']]
        }
        return {
            'type': 'fus',
            'data': {
                'id': fu['_id'],
                'rule_name': fu['_source']['rule_name'],
                'is_enabled': fu['_source']['is_enabled'],
                'target_field': fu['_source']['target_field'],
                'ip_root_cause_field': fu['_source']['ip_root_cause_field'],
                'regex_matcher': fu['_source']['regex_matcher'],
                'rule_library': choice_rules,
                'yara_rule_intergration': fu['_source']['yara_rule_intergration'],
                'action_id': choice_actions,
                'type_attack': fu['_source']['type_attack']
            },
            'reason': 'Success'
        }
    
    def get_action_name_by_id(self, id: str):
        action_type = response_elasticsearch.get(index='analyzer-actions', id=id)
        return action_type.raw['_source']['action_name']
