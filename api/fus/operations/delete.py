from flask_restful import Resource
from ...storage import response_elasticsearch


class FileUploadRuleTerminations(Resource):
    def delete(self, id):
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
            fu = response_elasticsearch.get(index='analyzer-fus', id=id)
        except:
            return {
                'type': 'fus',
                'data': None,
                'reason': 'NotFound: File Upload Rule is not found for delete'
            }, 404
        response_elasticsearch.delete(index='analyzer-fus', id=fu.raw['_id'])
        return {
            'type': 'fus',
            'data': {
                'id': fu.raw['_id']
            },
            'reason': 'Success'
        }
