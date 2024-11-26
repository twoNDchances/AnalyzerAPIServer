from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from json import dumps, loads
import re
import smtplib
import requests
from .storage import response_elasticsearch, ES_MAX_RESULT


def get_value_from_json(data, path: str):
    keys = re.split(r'\.(?![^\[]*\])', path)
    for key in keys:
        match = re.match(r'([\w\-]+)(\[(\d+)\])?', key)
        if not match:
            return None
        key, _, index = match.groups()
        if isinstance(data, dict):
            data = data.get(key)
            if data is None:
                return None
        else:
            return None
        if index is not None:
            try:
                index = int(index)
                data = data[index]
            except (IndexError, TypeError, ValueError):
                return None
    return data


def parse_path(path: str) -> list[str] | str | None:
    if path.startswith("[") and path.endswith("]"):
        paths = re.split(r',\s*', path[1:-1].strip())
        if all(re.match(r'^[\w\.-]+$', p) for p in paths):
            return paths
        else:
            return None
    elif re.match(r'^[\w\.-]+$', path):
        return path
    else:
        return None


def is_valid_regex(pattern):
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def traverse_json(data, parent_key='') -> list[dict]:
    paths = []
    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{parent_key}.{key}" if parent_key else key
            paths.extend(traverse_json(value, new_key))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            new_key = f"{parent_key}[{index}]"
            paths.extend(traverse_json(item, new_key))
    else:
        paths.append({parent_key: data})
    return paths


def replace_variables(user_input, variables):
    def replacer(match):
        var_name = match.group(1)
        return str(variables.get(var_name, f"${{{var_name}}}")) 
    if isinstance(user_input, str):
        return re.sub(r"\$([a-zA-Z_][a-zA-Z0-9_]*)", replacer, user_input)    
    elif isinstance(user_input, dict):
        result_dict = {}
        for key, value in user_input.items():
            if isinstance(value, str):
                result_dict[key] = re.sub(r"\$([a-zA-Z_][a-zA-Z0-9_]*)", replacer, value)
            elif isinstance(value, dict):
                result_dict[key] = replace_variables(value, variables)
            else:
                result_dict[key] = value
        return result_dict
    else:
        return user_input


def execute_action(action_type: str, action_configuration: dict, virtual_variable_list: dict, default_body: dict, ip_root_cause: str):
    if action_type == 'webhook':
        url = action_configuration.get('url')
        method = action_configuration.get('method')
        type = action_configuration.get('type')
        if not all([url, method, type]):
            return False
        if str(method).lower() not in ['get', 'post', 'put', 'patch', 'delete']:
            return False
        if type not in ['default', 'custom']:
            return False
        body = action_configuration.get('body')
        final_body = None
        if type == 'default':
            final_body = default_body
        if type == 'custom':
            if not body or not isinstance(body, dict):
                return False
            # try:
            #     final_body = loads(replace_variables(user_input=dumps(body), variables=virtual_variable_list))
            # except:
            #     final_body = {'payload': replace_variables(user_input=dumps(body), variables=virtual_variable_list)}
            final_body = {'payload': replace_variables(user_input=body, variables=virtual_variable_list)}
            final_body['ip_root_cause'] = ip_root_cause
        try:
            timeout = (action_configuration.get('connection_timeout'), action_configuration.get('data_read_timeout'))
            headers = {"Content-Type": "application/json"}
            if str(method).upper() == 'GET':
                response = requests.get(url=url, headers=headers, json={'message': 'GET method can\'t have body'}, timeout=timeout)
                if response.status_code != 200:
                    return False
                return True
            if str(method).upper() == 'POST':
                response = requests.post(url=url, headers=headers, json=final_body, timeout=timeout)
                if response.status_code != 200:
                    return False
                return True
            if str(method).upper() == 'PUT':
                response = requests.put(url=url, headers=headers, json=final_body, timeout=timeout)
                if response.status_code != 200:
                    return False
                return True
            if str(method).upper() == 'PATCH':
                response = requests.patch(url=url, headers=headers, json=final_body, timeout=timeout)
                if response.status_code != 200:
                    return False
                return True
            if str(method).upper() == 'DELETE':
                response = requests.delete(url=url, headers=headers, json=final_body)
                if response.status_code != 200:
                    return False
                return True
            return False
        except:
            return False
    if action_type == 'email':
        to = action_configuration.get('to')
        subject = action_configuration.get('subject')
        type = action_configuration.get('type')
        body = action_configuration.get('body')
        smtp = action_configuration.get('smtp')
        if not all([to, subject, type, smtp]):
            return False
        if type not in ['default', 'custom']:
            return False
        if type == 'default':
            final_body = default_body
        if type == 'custom':
            if not body or not isinstance(body, dict):
                return False
            final_body = replace_variables(user_input=body, variables=virtual_variable_list)
        if not isinstance(smtp, dict):
            return False
        smtp_host = smtp.get('host')
        smtp_port = smtp.get('port')
        smtp_username = smtp.get('username')
        smtp_password = smtp.get('password')
        if not all([smtp_host, smtp_port, smtp_username, smtp_password]):
            return False
        message = MIMEMultipart()
        message['From'] = smtp_username
        message['To'] = to
        message['Subject'] = subject
        text_body = f'[Warning] Suspicious log detected from Analyzer, result:'
        message.attach(MIMEText(text_body, 'plain'))
        json_data = dumps(final_body, indent=4).encode('utf-8')
        filename = 'result.json'
        part = MIMEBase('application', 'json')
        part.set_payload(json_data)
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename={filename}',
        )
        message.attach(part)
        try:
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(smtp_username, to, message.as_string())
            server.quit()
        except:
            return False
        return True
    return False


def check_threshold(analyzer: str, rule_name: str, action_name: str, action_configuration: dict, action_timestamp_id: str):
    advanced = dict(action_configuration.get('advanced'))
    is_enabled: bool = advanced.get('is_enabled')
    threshold: int = advanced.get('threshold')
    time_window_seconds: int = advanced.get('time_window_seconds')
    if is_enabled is False:
        return True
    now = int(datetime.now().timestamp())
    start_time = now - time_window_seconds
    action_timestamps = response_elasticsearch.search(index='analyzer-action-timestamps', query={'bool': {
        'must': [
            {'term': {
                'analyzer.keyword': analyzer
            }},
            {'term': {
                'rule_name.keyword': rule_name
            }},
            {'term': {
                'action_name.keyword': action_name
            }}
        ]
    }}, size=ES_MAX_RESULT).raw
    trigger_timestamps = [
        action_timestamp['_source']['timestamp'] for action_timestamp in action_timestamps['hits']['hits']
        if start_time <= action_timestamp['_source']['timestamp'] <= now
    ]
    if trigger_timestamps.__len__() == 0:
        response_elasticsearch.delete_by_query(index='analyzer-action-timestamps', query={
            'bool': {
                'must_not': [
                    {'term': {'_id': action_timestamp_id}},
                    {'term': {'analyzer.keyword': analyzer}},
                    {'term': {'rule_name.keyword': rule_name}},
                    {'term': {'action_name.keyword': action_name}}
                ]
            }
        })
    if trigger_timestamps.__len__() >= threshold:
        return True
    return False
