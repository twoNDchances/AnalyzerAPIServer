from flask_restful import Resource
from ...storage import response_elasticsearch


class RuleManifests(Resource):
    def get(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if id is None:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'BadRequest: ID required'
            }, 400
        try:
            rule = response_elasticsearch.get(index='analyzer-rules', id=id).raw
        except:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'rules',
            'data': {
                'id': rule['_id'],
                'rule_type': rule['_source']['rule_type'],
                'rule_execution': rule['_source']['rule_execution'],
                'rule_description': rule['_source']['rule_description']
            },
            'reason': 'Success'
        }
