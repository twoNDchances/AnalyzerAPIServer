from flask import request
from flask_restful import Resource
from json import loads
from ...storage import response_elasticsearch, ES_MAX_RESULT


class YARARuleCreations(Resource):
    def post(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'yaras',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
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
                'reason': 'BadRequest: "yaraRule" and "yaraDescription" is required'
            }, 400
        if isinstance(yara_rule, str) and isinstance(yara_description, str):
            if yara_rule.__len__() == 0 or yara_description.__len__() == 0:
                return {
                    'type': 'yaras',
                    'data': None,
                    'reason': 'NotAcceptable: Both YARA Rule and YARA Description is required'
                }, 406
            else:
                response_elasticsearch.index(index='analyzer-yaras', document={
                    'yara_rule': self.format_yara_rule(rule_input=yara_rule),
                    'yara_description': self.format_yara_rule(rule_input=yara_description),
                    'yara_rule_original': yara_rule,
                    'yara_description_original': yara_description
                })
        else:
            if isinstance(yara_rule, list) and isinstance(yara_description, list):
                for rule, description in zip(yara_rule, yara_description):
                    if rule.__len__() == 0 or description.__len__() == 0:
                        return {
                            'type': 'yaras',
                            'data': None,
                            'reason': 'NotAcceptable: Both Rule Execution and Rule Description is required'
                        }, 406
                    response_elasticsearch.index(index='analyzer-yaras', document={
                        'yara_rule': self.format_yara_rule(rule_input=rule),
                        'yara_description': self.format_yara_rule(rule_input=description),
                        'yara_rule_original': rule,
                        'yara_description_original': description
                    })
            else:
                return {
                    'type': 'yaras',
                    'data': None,
                    'reason': 'NotAcceptable: Both YARA Rule and YARA Description is required'
                }, 406
        return {
            'type': 'yaras',
            'data': None,
            'reason': 'Success'
        }

    def format_yara_rule(self, rule_input: str):
        lines = rule_input.strip().split("\n")        
        formatted_lines = []
        for line in lines:
            formatted_lines.append(line.strip())
        yara_rule = " ".join(formatted_lines)
        return yara_rule
