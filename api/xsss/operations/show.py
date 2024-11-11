from flask_restful import Resource
from ...storage import response_elasticsearch


class CrossSiteScriptingRuleDetails(Resource):
    def get(self, id):
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
            'choice': 'not_used' if xss.raw['_source']['rule_library'] is None else xss['_source']['rule_library'],
            'rules': [rule_type['key'] for rule_type in rule_types.raw['aggregations']['unique_names']['buckets']]
        }
        actions = response_elasticsearch.search(index='analyzer-actions', query={'match_all': {}}, size=1000000000)
        choice_actions = {
            'choice': 'not_used' if xss['_source']['action_id'] is None else self.get_action_name_by_id(id=xss['_source']['action_id']),
            'actions': [action['_source']['action_name'] for action in actions.raw['hits']['hits']]
        }
        return {
            'type': 'xsss',
            'data': {
                'id': xss['_id'],
                'rule_name': xss['_source']['rule_name'],
                'is_enabled': xss['_source']['is_enabled'],
                'target_field': xss['_source']['target_field'],
                'ip_root_cause_field': xss['_source']['ip_root_cause_field'],
                'regex_matcher': xss['_source']['regex_matcher'],
                'rule_library': choice_rules,
                'action_id': choice_actions,
                'type_attack': xss['_source']['type_attack']
            },
            'reason': 'Success'
        }
    
    def get_action_name_by_id(self, id: str):
        action_type = response_elasticsearch.get(index='analyzer-actions', id=id)
        return action_type.raw['_source']['action_name']
