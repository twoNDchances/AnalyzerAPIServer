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
        sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={'match_all': {}}, size=ES_MAX_RESULT).raw['hits']['hits']
        sqli_results = []; xss_results = []; fu_results = []
        for sqli in sqlis:
            sqli_results.append({
                'id': sqli['_id'],
                'analyzer': 'SQLi',
                'reference': sqli['_source']['rule_name'],
                'match_count': response_elasticsearch.search(
                    index='analyzer-results', 
                    query={
                        'bool': {
                            'must': [
                                {'term': {'analyzer.keyword': 'sqli'}},
                                {'term': {'reference.keyword': sqli['_source']['rule_name']}},
                                {'term': {'type.keyword': 'match_count'}}
                            ]
                        }
                    }, 
                    size=ES_MAX_RESULT
                ).raw['hits']['hits'].__len__(),
                'execution_count': response_elasticsearch.search(
                    index='analyzer-results', 
                    query={
                        'bool': {
                            'must': [
                                {'term': {'analyzer.keyword': 'sqli'}},
                                {'term': {'reference.keyword': sqli['_source']['rule_name']}},
                                {'term': {'type.keyword': 'execution_count'}}
                            ]
                        }
                    }, 
                    size=ES_MAX_RESULT
                ).raw['hits']['hits'].__len__()
            })
        xsss = response_elasticsearch.search(index='analyzer-xsss', query={'match_all': {}}, size=ES_MAX_RESULT).raw['hits']['hits']
        for xss in xsss:
            xss_results.append({
                'id': xss['_id'],
                'analyzer': 'XSS',
                'reference': xss['_source']['rule_name'],
                'match_count': response_elasticsearch.search(
                    index='analyzer-results', 
                    query={
                        'bool': {
                            'must': [
                                {'term': {'analyzer.keyword': 'xss'}},
                                {'term': {'reference.keyword': xss['_source']['rule_name']}},
                                {'term': {'type.keyword': 'match_count'}}
                            ]
                        }
                    }, 
                    size=ES_MAX_RESULT
                ).raw['hits']['hits'].__len__(),
                'execution_count': response_elasticsearch.search(
                    index='analyzer-results', 
                    query={
                        'bool': {
                            'must': [
                                {'term': {'analyzer.keyword': 'xss'}},
                                {'term': {'reference.keyword': xss['_source']['rule_name']}},
                                {'term': {'type.keyword': 'execution_count'}}
                            ]
                        }
                    }, 
                    size=ES_MAX_RESULT
                ).raw['hits']['hits'].__len__()
            })
        fus = response_elasticsearch.search(index='analyzer-fus', query={'match_all': {}}, size=ES_MAX_RESULT).raw['hits']['hits']
        for fu in fus:
            fu_results.append({
                'id': fu['_id'],
                'analyzer': 'FU',
                'reference': fu['_source']['rule_name'],
                'match_count': response_elasticsearch.search(
                    index='analyzer-results', 
                    query={
                        'bool': {
                            'must': [
                                {'term': {'analyzer.keyword': 'fu'}},
                                {'term': {'reference.keyword': fu['_source']['rule_name']}},
                                {'term': {'type.keyword': 'match_count'}}
                            ]
                        }
                    }, 
                    size=ES_MAX_RESULT
                ).raw['hits']['hits'].__len__(),
                'execution_count': response_elasticsearch.search(
                    index='analyzer-results', 
                    query={
                        'bool': {
                            'must': [
                                {'term': {'analyzer.keyword': 'fu'}},
                                {'term': {'reference.keyword': fu['_source']['rule_name']}},
                                {'term': {'type.keyword': 'execution_count'}}
                            ]
                        }
                    }, 
                    size=ES_MAX_RESULT
                ).raw['hits']['hits'].__len__()
            })
        all_results = sqli_results + xss_results + fu_results
        if all_results.__len__() == 0:
            return {
                'type': 'results',
                'data': None,
                'reason': 'NotFound'
            }, 404
        return {
            'type': 'results',
            'data': all_results,
            'reason': 'Success'
        }
