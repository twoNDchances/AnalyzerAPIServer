from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class ResultManifests(Resource):
    def get(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'results',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if id is None:
            return {
                'type': 'results',
                'data': None,
                'reason': 'BadRequest: ID is required'
            }, 400
        try:
            result = response_elasticsearch.get(index='analyzer-results', id=id)
        except:
            return {
                'type': 'results',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'results',
            'data': {
                'id': result.raw['_id'],
                'logs': result.raw['_source']['logs']
            },
            'reason': 'Success'
        }
