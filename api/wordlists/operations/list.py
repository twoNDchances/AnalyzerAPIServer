from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class WordlistLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
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
        if wordlist_names.__len__() == 0:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'NotFound'
            }, 404
        wordlist = []
        for wordlist_name in wordlist_names:
            wordlist.append({
                'wordlist_name': wordlist_name['key'],
                'count': response_elasticsearch.search(index='analyzer-wordlists', query={
                    'term': {
                        'wordlist_name.keyword': wordlist_name['key']
                    }
                }, size=ES_MAX_RESULT).raw['hits']['hits'].__len__()
            })
        return {
            'type': 'wordlists',
            'data': wordlist,
            'reason': 'Success'
        }


class WordlistNames(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'wordlists',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
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
        return {
            'type': 'wordlists',
            'data': [wordlist_name['key'] for wordlist_name in wordlist_names],
            'reason': 'Success'
        }


class WordlistRelatedLists(Resource):
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
        sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={
            'term': {
                'wordlist.keyword': wordlist_name
            }
        }, size=ES_MAX_RESULT).raw['hits']['hits']
        return {
            'type': 'wordlists',
            'data': [sqli['_source']['rule_name'] for sqli in sqlis],
            'reason': 'Success'
        }
