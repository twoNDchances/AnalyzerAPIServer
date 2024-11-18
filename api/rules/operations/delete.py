from flask import request
from flask_restful import Resource
from ...storage import response_elasticsearch, ES_MAX_RESULT


class RuleTerminations(Resource):
    def get(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        rule_type = None
        if id == '_':
            rule_type = request.args.get('ruleType')
            if rule_type is None:
                return {
                    'type': 'rules',
                    'data': None,
                    'reason': 'BadRequest: ID required'
                }, 400
        else:
            try:
                rule = response_elasticsearch.get(index='analyzer-rules', id=id).raw
            except:
                return {
                    'type': 'rules',
                    'data': None,
                    'reason': 'NotFound: Rule is not found'
                }, 404
        sqli_related_list = []
        sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={'term': {'rule_library.keyword': rule_type if rule_type is not None else rule['_source']['rule_type']}}, size=ES_MAX_RESULT)
        sqli_results = sqlis.raw['hits']['hits']
        if sqli_results.__len__() > 0:
            for sqli_result in sqli_results:
                sqli_related_list.append(sqli_result['_source']['rule_name'])
        xss_related_list = []
        xsss = response_elasticsearch.search(index='analyzer-xsss', query={'term': {'rule_library.keyword': rule_type if rule_type is not None else rule['_source']['rule_type']}}, size=ES_MAX_RESULT)
        xss_results = xsss.raw['hits']['hits']
        if xss_results.__len__() > 0:
            for xss_result in xss_results:
                xss_related_list.append(xss_result['_source']['rule_name'])
        fu_related_list = []
        fus = response_elasticsearch.search(index='analyzer-fus', query={'term': {'rule_library.keyword': rule_type if rule_type is not None else rule['_source']['rule_type']}}, size=ES_MAX_RESULT)
        fu_results = fus.raw['hits']['hits']
        if fu_results.__len__() > 0:
            for fu_result in fu_results:
                fu_related_list.append(fu_result['_source']['rule_name'])
        return {
            'type': 'rules',
            'data': {
                'sqli': sqli_related_list,
                'xss': xss_related_list,
                'fu': fu_related_list
            },
            'reason': 'Success'
        }

    def delete(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'rules',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        forbidden_list = ['SQLI', 'XSS', 'FU']
        if id == '_':
            rule_type = request.args.get('ruleType')
            if rule_type is None:
                return {
                    'type': 'rules',
                    'data': None,
                    'reason': 'BadRequest: ID required'
                }, 400
            rule_libraries = response_elasticsearch.search(index='analyzer-rules', query={'term': {'rule_type.keyword': rule_type}}, size=ES_MAX_RESULT)
            rule_library_results = rule_libraries.raw['hits']['hits']
            if rule_library_results.__len__() == 0:
                return {
                    'type': 'rules',
                    'data': None,
                    'reason': 'NotFound: Rule Library not found'
                }, 404
            for rule_library_result in rule_library_results:
                if rule_library_result['_source']['rule_type'] in forbidden_list:
                    return {
                        'type': 'rules',
                        'data': None,
                        'reason': 'Forbidden: Rule Library default can\'t delete'
                    }, 403
                response_elasticsearch.delete(index='analyzer-rules', id=rule_library_result['_id'])
            sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={'term': {'rule_library.keyword': rule_type}}, size=ES_MAX_RESULT)
            sqli_results = sqlis.raw['hits']['hits']
            if sqli_results.__len__() > 0:
                for sqli_result in sqli_results:
                    response_elasticsearch.update(index='analyzer-sqlis', id=sqli_result['_id'], doc={
                        'rule_library': 'SQLI'
                    })
            xsss = response_elasticsearch.search(index='analyzer-xsss', query={'term': {'rule_library.keyword': rule_type}}, size=ES_MAX_RESULT)
            xss_results = xsss.raw['hits']['hits']
            if xss_results.__len__() > 0:
                for xss_result in xss_results:
                    response_elasticsearch.update(index='analyzer-xsss', id=xss_result['_id'], doc={
                        'rule_library': 'XSS'
                    })
            fus = response_elasticsearch.search(index='analyzer-fus', query={'term': {'rule_library.keyword': rule_type}}, size=ES_MAX_RESULT)
            fu_results = fus.raw['hits']['hits']
            if fu_results.__len__() > 0:
                for fu_result in fu_results:
                    response_elasticsearch.update(index='analyzer-fus', id=fu_result['_id'], doc={
                        'rule_library': 'FU'
                    })
        else:
            try:
                rule_library = response_elasticsearch.get(index='analyzer-rules', id=id)
            except:
                return {
                    'type': 'rules',
                    'data': None,
                    'reason': 'NotFound: Rule is not found for delete'
                }, 404
            if rule_library.raw['_source']['rule_type'] in forbidden_list:
                return {
                    'type': 'rules',
                    'data': None,
                    'reason': 'Forbidden: Rule Library default can\'t delete'
                }, 403
            rule_libraries = response_elasticsearch.search(index='analyzer-rules', query={'term': {'rule_type.keyword': rule_library.raw['_source']['rule_type']}}, size=ES_MAX_RESULT)
            rule_library_results = rule_libraries.raw['hits']['hits']
            if rule_library_results.__len__() == 1:
                sqlis = response_elasticsearch.search(index='analyzer-sqlis', query={'term': {'rule_library.keyword': rule_library.raw['_source']['rule_type']}}, size=ES_MAX_RESULT)
                sqli_results = sqlis.raw['hits']['hits']
                if sqli_results.__len__() > 0:
                    for sqli_result in sqli_results:
                        response_elasticsearch.update(index='analyzer-sqlis', id=sqli_result['_id'], doc={
                            'rule_library': 'SQLI'
                        })
                xsss = response_elasticsearch.search(index='analyzer-xsss', query={'term': {'rule_library.keyword': rule_library.raw['_source']['rule_type']}}, size=ES_MAX_RESULT)
                xss_results = xsss.raw['hits']['hits']
                if xss_results.__len__() > 0:
                    for xss_result in xss_results:
                        response_elasticsearch.update(index='analyzer-xsss', id=xss_result['_id'], doc={
                            'rule_library': 'XSS'
                        })
                fus = response_elasticsearch.search(index='analyzer-fus', query={'term': {'rule_library.keyword': rule_library.raw['_source']['rule_type']}}, size=ES_MAX_RESULT)
                fu_results = fus.raw['hits']['hits']
                if fu_results.__len__() > 0:
                    for fu_result in fu_results:
                        response_elasticsearch.update(index='analyzer-fus', id=fu_result['_id'], doc={
                            'rule_library': 'FU'
                        })
            response_elasticsearch.delete(index='analyzer-rules', id=rule_library.raw['_id'])
        return {
            'type': 'rules',
            'data': None,
            'reason': 'Success'
        }