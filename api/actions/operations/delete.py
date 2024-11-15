from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class ActionTerminations(Resource):
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
        sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={'match_phrase': {'action_id': action.raw['_id']}}, size=ES_MAX_RESULT)
        sqli_results = sqlis.raw['hits']['hits']
        if sqli_results.__len__() > 0:
            for sqli_result in sqli_results:
                sqli_related_actions.append(sqli_result['_source']['rule_name'])
        xss_related_actions = []
        xsss = response_elasticsearch.search(index='analyzer-xsss', query={'match_phrase': {'action_id': action.raw['_id']}}, size=ES_MAX_RESULT)
        xss_results = xsss.raw['hits']['hits']
        if xss_results.__len__() > 0:
            for xss_result in xss_results:
                xss_related_actions.append(xss_result['_source']['rule_name'])
        fu_related_actions = []
        fus = response_elasticsearch.search(index='analyzer-fus', query={'match_phrase': {'action_id': action.raw['_id']}}, size=ES_MAX_RESULT)
        fu_results = fus.raw['hits']['hits']
        if fu_results.__len__() > 0:
            for fu_result in fu_results:
                fu_related_actions.append(fu_result['_source']['rule_name'])
        return {
            'type': 'actions',
            'data': {
                'sqli': sqli_related_actions,
                'xss': xss_related_actions,
                'fu': fu_related_actions
            },
            'reason': 'Success'
        }


    def delete(self, id):
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
        sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={'match_phrase': {'action_id': action.raw['_id']}}, size=ES_MAX_RESULT)
        sqli_results = sqlis.raw['hits']['hits']
        if sqli_results.__len__() > 0:
            for sqli_result in sqli_results:
                response_elasticsearch.update(index='analyzer-sqlis', id=sqli_result['_id'], doc={
                    'action_id': None
                })
        xsss = response_elasticsearch.search(index='analyzer-xsss', query={'match_phrase': {'action_id': action.raw['_id']}}, size=ES_MAX_RESULT)
        xss_results = xsss.raw['hits']['hits']
        if xss_results.__len__() > 0:
            for xss_result in xss_results:
                response_elasticsearch.update(index='analyzer-xsss', id=xss_result['_id'], doc={
                    'action_id': None
                })
        fus = response_elasticsearch.search(index='analyzer-fus', query={'match_phrase': {'action_id': action.raw['_id']}}, size=ES_MAX_RESULT)
        fu_results = fus.raw['hits']['hits']
        if fu_results.__len__() > 0:
            for fu_result in fu_results:
                response_elasticsearch.update(index='analyzer-fus', id=fu_result['_id'], doc={
                    'action_id': None
                })
        response_elasticsearch.delete(index='analyzer-actions', id=action.raw['_id'])
        return {
            'type': 'actions',
            'data': {
                'action_type': action.raw['_source']['action_type'],
                'id': action.raw['_id']
            },
            'reason': 'Success'
        }
