from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from re import match
import smtplib
from flask import request
from flask_restful import Resource
from json import dumps, loads
from requests import get
from ...storage import response_elasticsearch, ES_MAX_RESULT


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
        advanced = action_configuration.get('advanced')
        if not advanced:
            action_configuration['advanced'] = {
                'is_enabled': False,
                'threshold': 0,
                'time_window_seconds': 0
            }
        else:
            if not isinstance(advanced, dict):
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'NotAcceptable: "advanced" field is invalid format'
                }, 406
            is_enabled = advanced.get('is_enabled')
            threshold = advanced.get('threshold')
            time_window_seconds = advanced.get('time_window_seconds')
            if not isinstance(is_enabled, bool):
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'NotAcceptable: "is_enabled" must be booleans'
                }, 406
            if not isinstance(threshold, int):
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'NotAcceptable: "threshold" must be an integer'
                }, 406
            if not isinstance(time_window_seconds, int):
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'NotAcceptable: "time_window_seconds" must be an integer'
                }, 406
        if action.raw['_source']['action_type'] == 'webhook':
            url = action_configuration.get("url")
            type = action_configuration.get("type")
            method = action_configuration.get('method')
            connection_timeout = action_configuration.get('connection_timeout')
            data_read_timeout = action_configuration.get('data_read_timeout')
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
            if not connection_timeout or not data_read_timeout:
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'BadRequest: "connection_timeout" and "data_read_timeout" is required'
                }, 400
            if not isinstance(connection_timeout, int) or not isinstance(data_read_timeout, int):
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'NotAcceptable: "connection_timeout" and "data_read_timeout" must be integers'
                }, 406
            else:
                connection_timeout = int(connection_timeout)
                data_read_timeout = int(data_read_timeout)
                if connection_timeout <= 1 or data_read_timeout < 3:
                    return {
                        'type': 'actions',
                        'data': None,
                        'reason': 'NotAcceptable: "connection_timeout" must be greater than 1 and "data_read_timeout" must be greater or equal to 3'
                    }, 406
            try:
                headers = {"Content-Type": "application/json"}
                response = get(url, headers=headers, json={}, timeout=(connection_timeout, data_read_timeout))
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
            to = action_configuration.get('to')
            subject = action_configuration.get('subject')
            type = action_configuration.get('type')
            body = action_configuration.get('body')
            smtp = action_configuration.get('smtp')
            if not all([to, subject, type, smtp]):
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'BadRequest: Missing required fields for email ["to", "subject", "type", "smtp"]'
                }, 400
            if not isinstance(to, str) or not isinstance(subject, str) or not isinstance(type, str) or not isinstance(smtp, dict):
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'NotAcceptable: Incorrect datatype ["to" => <string>, "subject" => <string>, "type" => <string>, "smtp" => <json>]'
                }, 406
            if type not in ['default', 'custom']:
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'NotAcceptable: "type" field must be in [default, custom]'
                }, 406
            if type == 'custom':
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
            smtp_host = smtp.get('host')
            smtp_port = smtp.get('port')
            smtp_username = smtp.get('username')
            smtp_password = smtp.get('password')
            if not all([smtp_host, smtp_port, smtp_username, smtp_password]):
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'BadRequest: Missing required fields for email "smtp" => ["host", "port", "username", "password"]'
                }, 400
            if not isinstance(smtp_host, str) or not isinstance(smtp_port, int) or not isinstance(smtp_username, str) or not isinstance(smtp_password, str):
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'NotAcceptable: Incorrect datatype ["host" => <string>, "port" => <integer>, "username" => <string>, "password" => <string>]'
                }, 406
            email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
            if not match(email_regex, smtp_username) or not match(email_regex, to):
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'NotAcceptable: Invalid email format'
                }, 406
            try:
                message = MIMEMultipart()
                message['From'] = smtp_username
                message['To'] = to
                message['Subject'] = subject
                message.attach(MIMEText('Test update Email configuration successfully'))
                if smtp_port == 465:
                    server = smtplib.SMTP_SSL(smtp_host, smtp_port)
                else:
                    server = smtplib.SMTP(smtp_host, smtp_port)
                    server.starttls()
                server.login(smtp_username, smtp_password)
                server.sendmail(smtp_username, to, message.as_string())
                server.quit()
            except:
                return {
                    'type': 'actions',
                    'data': None,
                    'reason': 'InternalServerError: Email sending failed fot testing'
                }, 500
        old_action_name = action.raw['_source']['action_name']
        old_action_configuration = action['_source']['action_configuration']
        action_name_flag = False
        action_configuration_flag = False
        if old_action_name != action_name:
            if response_elasticsearch.search(index='analyzer-actions', query={
                'term': {
                    'action_name.keyword': action_name
                }
            }, size=ES_MAX_RESULT).raw['hits']['hits'].__len__() > 0:
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
