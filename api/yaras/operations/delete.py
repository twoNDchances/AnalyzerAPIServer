from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class YARARuleTerminations(Resource):
    def get(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        fus = response_elasticsearch.search(index='analyzer-fus', query={'term': {'yara_rule_intergration.keyword': True}}, size=ES_MAX_RESULT)
        return {
            'type': 'yaras',
            'data': [fu['_source']['rule_name'] for fu in fus.raw['hits']['hits']],
            'reason': 'Success'
        }

    def delete(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if id is None:
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
        response_elasticsearch.delete(index='analyzer-yaras', id=yara.raw['_id'])
        return {
            'type': 'yaras',
            'data': {
                'id': yara.raw['_id']
            },
            'reason': 'Success'
        }
