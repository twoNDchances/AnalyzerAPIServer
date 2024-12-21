from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class WordlistShow(Resource):
    def get(self, wordlist_name: str):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not wordlist_name:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'BadRequest: Wordlist Name is required'
            }, 400
        wordlists = response_elasticsearch.search(index='analyzer-wordlists', query={
            'term': {
                'wordlist_name.keyword': wordlist_name
            }
        }, size=ES_MAX_RESULT).raw['hits']['hits']
        if wordlists.__len__() == 0:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'NotFound'
            }, 404
        sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={
            'term': {
                'wordlist.keyword': wordlist_name
            }
        }, size=ES_MAX_RESULT).raw['hits']['hits']
        return {
            'type': 'wordlists',
            'data': {
                'wordlist_name': wordlist_name,
                'content': [wordlist['_source']['content'] for wordlist in wordlists],
                'related': [sqli['_source']['rule_name'] for sqli in sqlis]
            },
            'reason': 'Success'
        }
