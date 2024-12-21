from flask import request
from flask_restful import Resource
from json import loads
from ...storage import response_elasticsearch, ES_MAX_RESULT


class WordlistModifications(Resource):
    def put(self, wordlist_name: str):
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
        wordlist_names = response_elasticsearch.search(index='analyzer-wordlists', body={
            "aggs":{
                "unique_names": {
                    "terms": {
                        "field": "wordlist_name.keyword"
                    }
                }
            },
            "_source": False
        }, size=ES_MAX_RESULT).raw['aggregations']['unique_names']['buckets']
        if wordlist_name not in [wordlist['key'] for wordlist in wordlist_names]:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'NotFound: Wordlist Name not found'
            }, 404
        try:
            loads(request.data)
        except:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body: dict = request.get_json()
        new_wordlist_name = request_body.get('wordlistName')
        new_content = request_body.get('content')
        if not all([new_wordlist_name, new_content]):
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'BadRequest: Missing required fields ["wordlist_name", "content"]'
            }, 400
        if not isinstance(new_wordlist_name, str) or not isinstance(new_content, list):
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["wordlist_name" => (string), "content" => (list)]'
            }, 406
        if new_content.__len__() == 0:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'NotAcceptable: "content" can\'t be empty'
            }, 406
        if new_wordlist_name != wordlist_name:
            if new_wordlist_name in [wordlist['key'] for wordlist in wordlist_names]:
                return {
                    'type': 'wordlists',
                    'data': None,
                    'reason': 'NotAcceptable: Wordlist Name is exists'
                }, 406
        response_elasticsearch.delete_by_query(index='analyzer-wordlists', query={
            'term': {
                'wordlist_name.keyword': wordlist_name
            }
        })
        for new_ctn in new_content:
            if new_ctn:
                response_elasticsearch.index(index='analyzer-wordlists', document={
                    'wordlist_name': new_wordlist_name,
                    'content': new_ctn
                })
        return {
            'type': 'wordlists',
            'data': {
                'wordlist_name': wordlist_name,
                'count': [_ for _ in new_content if _].__len__()
            },
            'reason': 'Success'
        }        
