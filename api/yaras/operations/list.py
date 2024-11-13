from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class YARARuleLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        yaras = response_elasticsearch.search(index='analyzer-yaras', query={'match_all': {}}, size=ES_MAX_RESULT)
        if yaras['hits']['hits'].__len__() == 0:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'NotFound: Not found any record of YARAs'
            }, 404
        return {
            'type': 'yaras',
            'data': [{
                'id': yara['_id'],
                'yara_rule': yara['_source']['yara_rule_original'],
                'yara_description': yara['_source']['yara_description_original'],
            } for yara in yaras['hits']['hits']],
            'reason': 'Success'
        }
