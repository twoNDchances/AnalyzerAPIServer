from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class WordlistTerminations(Resource):
    def delete(self, wordlist_name: str):
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
        response_elasticsearch.delete_by_query(index='analyzer-wordlists', query={
            'term': {
                'wordlist_name.keyword': wordlist_name
            }
        })
        sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={
            'term': {
                'wordlist.keyword': wordlist_name
            }
        }, size=ES_MAX_RESULT).raw['hits']['hits']
        for sqli in sqlis:
            response_elasticsearch.update(index='analyzer-sqlis', id=sqli['_id'], doc={
                'wordlist': None
            })
        return {
            'type': 'wordlists',
            'data': wordlist_name,
            'reason': 'Success'
        }
