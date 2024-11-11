from flask import request
from flask_restful import Resource
from json import loads, dumps
from requests import get
from ...storage import response_elasticsearch


class ActionCreations(Resource):
    def post(self, kind):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'actions',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if kind is None:
            return {
                'type': 'actions',
                'data': None,
                'reason': 'BadRequest: Action Kind required'
            }, 400
        action_list = [
            'webhook',
            'email'
        ]
        if kind not in action_list:
            return {
                'type': 'actions',
                'data': None,
                'reason': 'NotFound: Action Kind not found'
            }, 404
        try:
            loads(request.data)
        except:
            return {
                'type': 'actions',
                'data': None,
                'reason': 'BadRequest: Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        action_name = request_body.get("actionName")
        action_configuration = request_body.get("actionConfiguration")
        if not all([action_name, action_configuration]):
            return {
                'type': 'actions',
                'data': None,
                'reason': 'BadRequest: Missing required fields'
            }, 400
        actions = response_elasticsearch.search(index='analyzer-actions', body={"query": {"match_all": {}}}, size=1000000000)
        for action in actions.raw['hits']['hits']:
            if action['_source']['action_name'] == action_name:
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'NotAcceptable: Action Name is exist'
                }, 406
        if not isinstance(action_configuration, dict):
            return {
                'type': 'actions',
                'data': None,
                'reason': 'BadRequest: Invalid configuration format'
            }, 400
        if kind == 'webhook':
            url = action_configuration.get("url")
            type = action_configuration.get("type")
            method = action_configuration.get('method')
            if not url:
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'BadRequest: "url" field is required'
                }, 400
            if not type:
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'BadRequest: "type" field is required'
                }, 400
            if type not in ['default', 'custom']:
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'NotAcceptable: "type" field must be in [default, custom]'
                }, 406
            if type == 'custom':
                body = action_configuration.get('body')
                if not body:
                    return {
                        'type': 'actions',
                        'data': None,
                        'reason': 'BadRequest: "body" field is required for custom type'
                    }, 400
                if not isinstance(body, dict):
                    return {
                        'type': 'actions',
                        'data': None,
                        'reason': 'BadRequest: "body" field must be JSON for custom type'
                    }, 400
            if not method:
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'BadRequest: "method" is required'
                }, 400
            if method.lower() not in ['post', 'get', 'put', 'patch', 'delete']:
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'BadRequest: "method" must be in [POST, GET, PUT, PATCH, DELETE]'
                }, 400
            try:
                headers = {"Content-Type": "application/json"}
                response = get(url, headers=headers, json={})
                if response.status_code != 200:
                    return {
                        'type': 'actions',
                        'data': None,
                        'reason': "BadRequest: Webhook test failed with status code: " + str(response.status_code)
                    }, 400
            except:
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': "InternalServerError: GET request to webhook for testing fail"
                }, 500
            response_elasticsearch.index(index='analyzer-actions', document={
                'action_name': action_name,
                'action_type': 'webhook',
                'action_configuration': dumps(action_configuration)
            })
            return {
                'type': 'actions',
                'data': None,
                'reason': 'Success'
            }
        if kind == 'email':
            return {
                'type': 'actions',
                'data': None,
                'reason': 'Success'
            }
        return {
            'type': 'actions',
            'data': None,
            'reason': "NotFound: Action Kind not found"
        }, 404


