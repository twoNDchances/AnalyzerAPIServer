from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class ResultLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'results',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        results = response_elasticsearch.search(index='analyzer-results', query={'match_all': {}}, size=ES_MAX_RESULT)
        all_results = results.raw['hits']['hits']
        if all_results.__len__() == 0:
            return {
                'type': 'results',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'results',
            'data': [{
                'id': result['_id'],
                'analyzer': result['_source']['analyzer'],
                'reference': result['_source']['reference'],
                'match_count': result['_source']['match_count'],
                'execution_count': result['_source']['execution_count'],
                'logs': result['_source']['logs'],
            } for result in all_results],
            'reason': 'Success'
        }
