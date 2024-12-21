from flask_restful import Resource
from ...storage import response_elasticsearch


class SQLInjectionRuleTerminations(Resource):
    def delete(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if id is None:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'BadRequest: ID required'
            }, 400
        try:
            sqli = response_elasticsearch.get(index='analyzer-sqlis', id=id)
        except:
            return {
                'type': 'sqlis',
                'data': None,
                'reason': 'NotFound: SQL Injection Rule is not found for delete'
            }, 404
        response_elasticsearch.delete(index='analyzer-sqlis', id=sqli.raw['_id'])
        response_elasticsearch.delete_by_query(index='analyzer-results', query={
            'bool': {
                'must': [
                    {'term': {'analyzer.keyword': 'sqli'}},
                    {'term': {'reference.keyword': sqli.raw['_source']['rule_name']}}
                ]
            }
        })
        response_elasticsearch.delete_by_query(index='analyzer-errorlogs', query={
            'bool': {
                'must': [
                    {'term': {'analyzer.keyword': 'sqli'}},
                    {'term': {'reference.keyword': sqli.raw['_source']['rule_name']}}
                ]
            }
        })
        response_elasticsearch.delete_by_query(index='analyzer-action-timestamps', query={
            'bool': {
                'must': [
                    {'term': {'analyzer.keyword': 'SQLIs'}},
                    {'term': {'rule_name.keyword': sqli.raw['_source']['rule_name']}}
                ]
            }
        })
        return {
            'type': 'sqlis',
            'data': {
                'id': sqli.raw['_id']
            },
            'reason': 'Success'
        }
