from flask import request
from flask_restful import Resource
from json import loads
from ...storage import response_elasticsearch, ES_MAX_RESULT


class YARARuleModifications(Resource):
    def get(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        fus = response_elasticsearch.search(index='analyzer-fus', query={'match_phrase': {'yara_rule_intergration': True}}, size=ES_MAX_RESULT)
        return {
            'type': 'fus',
            'data': [fu['_source']['rule_name'] for fu in fus.raw['hits']['hits']],
            'reason': 'Success'
        }


    def put(self, id):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if not id:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'BadRequest: ID is required'
            }, 400
        try:
            yara = response_elasticsearch.get(index='analyzer-yaras', id=id)
        except:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'NotFound'
            }, 404
        try:
            loads(request.data)
        except:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        yara_rule = request_body.get('yaraRule')
        yara_description = request_body.get('yaraDescription')
        if yara_rule is None or yara_description is None:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'BadRequest: Lack of requirement fill'
            }, 400
        if isinstance(yara_rule, str) and isinstance(yara_description, str):
            if yara_rule.__len__() == 0 or yara_description.__len__() == 0:
                return {
                    'type': 'yaras',
                    'data': None,
                    'reason': 'NotAcceptable: Both YARA Rule and YARA Description is required'
                }, 406
        if yara.raw['_source']['yara_rule'] != yara_rule or yara.raw['_source']['yara_description']:
            response_elasticsearch.update(index='analyzer-yaras', id=yara.raw['_id'], doc={
                'yara_rule': self.format_yara_rule(rule_input=yara_rule),
                'yara_description': self.format_yara_rule(rule_input=yara_description),
                'yara_rule_original': yara_rule,
                'yara_description_original': yara_description
            })
        return {
            'type': 'yaras',
            'data': {
                'id': yara.raw['_id'],
                'yara_rule': yara_rule,
                'yara_description': yara_description
            },
            'reason': 'Success'
        }


    def format_yara_rule(self, rule_input: str):
        lines = rule_input.strip().split("\n")        
        formatted_lines = []
        for line in lines:
            formatted_lines.append(line.strip())
        yara_rule = " ".join(formatted_lines)
        return yara_rule