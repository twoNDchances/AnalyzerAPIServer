import re
import requests


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
    result = re.sub(r"\$([a-zA-Z_][a-zA-Z0-9_]*)", replacer, user_input)
    return result


def execute_action(action_type: str, action_configuration: dict, virtual_variable_list: dict, default_body: dict):
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
            final_body = replace_variables(user_input=str(body), variables=virtual_variable_list)
        try:
            if str(method).upper() == 'GET':
                response = requests.get(url=url, headers={"Content-Type": "application/json"}, json=final_body)
                if response.status_code != 200:
                    return False
                return True
            if str(method).upper() == 'POST':
                response = requests.post(url=url, headers={"Content-Type": "application/json"}, json=final_body)
                if response.status_code != 200:
                    return False
                return True
            if str(method).upper() == 'PUT':
                response = requests.put(url=url, headers={"Content-Type": "application/json"}, json=final_body)
                if response.status_code != 200:
                    return False
                return True
            if str(method).upper() == 'PATCH':
                response = requests.patch(url=url, headers={"Content-Type": "application/json"}, json=final_body)
                if response.status_code != 200:
                    return False
                return True
            if str(method).upper() == 'DELETE':
                response = requests.delete(url=url, headers={"Content-Type": "application/json"}, json=final_body)
                if response.status_code != 200:
                    return False
                return True
            return False
        except:
            return False
    if action_type == 'email':
        return True
    return False
