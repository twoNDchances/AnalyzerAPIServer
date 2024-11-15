from flask_restful import Resource
from ...storage import response_elasticsearch


class YARARuleManifests(Resource):
    def get(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not id:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'BadRequest: ID is required'
            }, 400
        try:
            yara = response_elasticsearch.get(index='analyzer-yaras', id=id)
        except:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'yaras',
            'data': {
                'id': yara.raw['_id'],
                'yara_rule': yara.raw['_source']['yara_rule_original'],
                'yara_description': yara.raw['_source']['yara_description_original']
            }
        }