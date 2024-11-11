from flask import request
from flask_restful import Resource
from json import dumps, loads
from requests import get
from ...storage import response_elasticsearch


class ActionModifications(Resource):
    def put(self, id):
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
        action_configuration = loads(request_body.get("actionConfiguration"))

        if not all([action_name, action_configuration]):
            return {
                'type': 'actions',
                'data': None,
                'reason': 'BadRequest: Missing required fields'
            }, 400
        if not isinstance(action_configuration, dict):
            return {
                'type': 'actions',
                'data': None,
                'reason': 'BadRequest: Invalid configuration format'
            }, 400
        if action.raw['_source']['action_type'] == 'webhook':
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
                    'reason': 'BadRequest: "type" field must be in [default, custom]'
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
        if action.raw['_source']['action_type'] == 'email':
            return {
                'type': 'actions',
                'data': None,
                'reason': 'Success'
            }
        old_action_name = action.raw['_source']['action_name']
        old_action_configuration = action['_source']['action_configuration']
        action_name_flag = False
        action_configuration_flag = False
        if old_action_name != action_name:
            if response_elasticsearch.search(index='analyzer-actions', query={
                'match_phrase': {
                    'action_name': action_name
                }
            }, size=1000000000).raw['hits']['hits'].__len__() > 0:
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'NotAcceptable: Action Name is exist'
                }, 406
            old_action_name = action_name
            action_name_flag = True
        if old_action_configuration != action_configuration:
            old_action_configuration = action_configuration
            action_configuration_flag = True
        if action_name_flag is True or action_configuration_flag is True:
            response_elasticsearch.update(index='analyzer-actions', id=action.raw['_id'], doc={
                'action_name': old_action_name,
                'action_configuration': dumps(old_action_configuration)
            })
        return {
            'type': 'actions',
            'data': {
                'id': action.raw['_id'],
                'action_name': old_action_name,
                'action_type': action.raw['_source']['action_type'],
                'action_configuration': old_action_configuration
            },
            'reason': 'Success'
        }
