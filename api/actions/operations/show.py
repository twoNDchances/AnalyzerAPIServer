from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class ActionDetails(Resource):
    def get(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'actions',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if id is None:
            return {
                'type': 'actions',
                'data': None,
                'reason': 'BadRequest: ID is required'
            }, 400
        try:
            action = response_elasticsearch.get(index='analyzer-actions', id=id)
        except:
            return {
                'type': 'actions',
                'data': None,
                'reason': 'NotFound: Action is not found'
            }, 404
        sqli_related_actions = []
        sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={'match_phrase': {'action_id': id}}, size=ES_MAX_RESULT)
        sqli_results = sqlis.raw['hits']['hits']
        if sqli_results.__len__() > 0:
            for sqli_result in sqli_results:
                sqli_related_actions.append(sqli_result['_source']['rule_name'])

        xss_related_actions = []
        xsss = response_elasticsearch.search(index='analyzer-xsss', query={'match_phrase': {'action_id': id}}, size=ES_MAX_RESULT)
        xss_results = xsss.raw['hits']['hits']
        if xss_results.__len__() > 0:
            for xss_result in xss_results:
                xss_related_actions.append(xss_result['_source']['rule_name'])
        return {
            'type': 'action',
            'data': {
                'id': action.raw['_id'],
                'action_name': action.raw['_source']['action_name'],
                'action_type': action.raw['_source']['action_type'],
                'action_configuration': action.raw['_source']['action_configuration'],
                'rule_related': {
                    'sqli': sqli_related_actions,
                    'xss': xss_related_actions
                }
            },
            'reason': 'Success'
        }
