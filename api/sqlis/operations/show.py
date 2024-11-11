from flask_restful import Resource
from ...storage import response_elasticsearch


class SQLInjectionRuleDetails(Resource):
    def get(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if id is None:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'BadRequest: ID required'
            }, 400
        try:
            sqli = response_elasticsearch.get(index='analyzer-sqlis', id=id)
        except:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'NotFound: SQL Injection Rule is not found for show'
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
                    size=1000000000
                )
        choice_rules = {
            'choice': 'not_used' if sqli['_source']['rule_library'] is None else sqli.raw['_source']['rule_library'],
            'rules': [rule_type['key'] for rule_type in rule_types.raw['aggregations']['unique_names']['buckets']]
        }
        actions = response_elasticsearch.search(index='analyzer-actions', query={'match_all': {}}, size=1000000000)
        choice_actions = {
            'choice': 'not_used' if sqli['_source']['action_id'] is None else self.get_action_name_by_id(id=sqli['_source']['action_id']),
            'actions': [action['_source']['action_name'] for action in actions.raw['hits']['hits']]
        }
        return {
            'type': 'sqlis',
            'data': {
                'id': sqli['_id'],
                'rule_name': sqli['_source']['rule_name'],
                'is_enabled': sqli['_source']['is_enabled'],
                'target_field': sqli['_source']['target_field'],
                'ip_root_cause_field': sqli['_source']['ip_root_cause_field'],
                'regex_matcher': sqli['_source']['regex_matcher'],
                'rule_library': choice_rules,
                'action_id': choice_actions,
                'type_attack': sqli['_source']['type_attack']
            },
            'reason': 'Success'
        }
    
    def get_action_name_by_id(self, id: str):
        action_type = response_elasticsearch.get(index='analyzer-actions', id=id)
        return action_type.raw['_source']['action_name']
