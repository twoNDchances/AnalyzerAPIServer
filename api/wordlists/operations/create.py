from flask import request
from flask_restful import Resource
from json import loads
from ...storage import response_elasticsearch, ES_MAX_RESULT


class WordlistCreations(Resource):
    def post(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        try:
            loads(request.data)
        except:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        wordlist_name = request_body.get('wordlist_name')
        content = request_body.get('content')
        if not all([wordlist_name, content]):
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'BadRequest: Missing required fields ["wordlist_name", "content"]'
            }, 400
        if not isinstance(wordlist_name, str) or not isinstance(content, list):
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'NotAcceptable: Invalid datatype ["wordlist_name" => (string), "content" => (list)]'
            }, 406
        if content.__len__() == 0:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'NotAcceptable: "content" can\'t be empty'
            }, 406
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
        if wordlist_name in [wordlist['key'] for wordlist in wordlist_names]:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'NotAcceptable: Wordlist Name is exists'
            }, 406
        for ctn in content:
            if ctn:
                response_elasticsearch.index(index='analyzer-wordlists', document={
                    'wordlist_name': wordlist_name,
                    'content': ctn
                })
        return {
            'type': 'wordlists',
            'data': None,
            'reason': 'Success'
        }
