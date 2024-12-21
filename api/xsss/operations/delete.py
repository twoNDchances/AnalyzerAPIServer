from flask_restful import Resource
from ...storage import response_elasticsearch


class CrossSiteScriptingRuleTerminations(Resource):
    def delete(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if id is None:
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'BadRequest: ID required'
            }, 400
        try:
            xss = response_elasticsearch.get(index='analyzer-xsss', id=id)
        except:
            return {
                'type': 'xsss',
                'data': None,
                'reason': 'NotFound: Cross Site Scripting Rule is not found for delete'
            }, 404
        response_elasticsearch.delete(index='analyzer-xsss', id=xss.raw['_id'])
        response_elasticsearch.delete_by_query(index='analyzer-results', query={
            'bool': {
                'must': [
                    {'term': {'analyzer.keyword': 'xss'}},
                    {'term': {'reference.keyword': xss.raw['_source']['rule_name']}}
                ]
            }
        })
        response_elasticsearch.delete_by_query(index='analyzer-errorlogs', query={
            'bool': {
                'must': [
                    {'term': {'analyzer.keyword': 'xss'}},
                    {'term': {'reference.keyword': xss.raw['_source']['rule_name']}}
                ]
            }
        })
        response_elasticsearch.delete_by_query(index='analyzer-action-timestamps', query={
            'bool': {
                'must': [
                    {'term': {'analyzer.keyword': 'XSSs'}},
                    {'term': {'rule_name.keyword': xss.raw['_source']['rule_name']}}
                ]
            }
        })
        return {
            'type': 'xsss',
            'data': {
                'id': xss.raw['_id']
            },
            'reason': 'Success'
        }
