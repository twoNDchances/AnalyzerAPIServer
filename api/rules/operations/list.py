from flask import request
from flask_restful import Resource
from ...storage import response_elasticsearch


class RuleLibraries(Resource):
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
        if request.args.get('ruleType') is not None:
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
            return {
                'type': 'rules',
                'data': [rule_type['key'] for rule_type in rule_types.raw['aggregations']['unique_names']['buckets']],
                'reason': 'Success'
            }
        rules = response_elasticsearch.search(index='analyzer-rules', body={"query": {"match_all": {}}}, size=1000000000)
        return {
            'type': 'rules',
            'data': [{
                'id': rule['_id'],
                'rule_type': rule['_source']['rule_type'],
                'rule_execution': rule['_source']['rule_execution'],
                'rule_description': rule['_source']['rule_description'],
            } for rule in rules.raw['hits']['hits']],
            'reason': 'Success'
        }