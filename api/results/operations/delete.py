from flask import request
from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class ErrorlogsTerminations(Resource):
    def delete(self, rule_name):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'errorlogs',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if rule_name is None:
            return {
                'type': 'errorlogs',
                'data': None,
                'reason': 'BadRequest: Rule Name is required'
            }, 400
        analyzer_type = request.args.get('type')
        if not analyzer_type or analyzer_type not in ['sqli', 'xss', 'fu']:
            return {
                'type': 'errorlogs',
                'data': None,
                'reason': 'BadRequest: Analyzer Type invalid, must in ["sqli", "xss", "fu]'
            }, 400
        response_elasticsearch.delete_by_query(index='analyzer-errorlogs', query={
            'bool': {
                'must': [
                    {'term': {'analyzer.keyword': analyzer_type}},
                    {'term': {'reference.keyword': rule_name}}
                ]
            }
        })
        return {
            'type': 'errorlogs',
            'data': None,
            'reason': 'Success'
        }
