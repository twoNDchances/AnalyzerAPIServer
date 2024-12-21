from flask import Flask, request
from flask_cors import CORS
from json import loads

from .rules import rule_main_blueprint

from .sqlis import sqli_main_blueprint
from .sqlis import sqli_analyzer_blueprint

from .xsss import xss_main_blueprint
from .xsss import xss_analyzer_blueprint

from .fus import fus_main_blueprint
from .fus import fus_analyzer_blueprint

from .yaras import yara_main_blueprint

from .wordlists import wordlist_main_blueprint

from .results import result_main_blueprint

from .actions import action_main_blueprint

from .resources import resource_main_blueprint

from .storage import load_rule_library, ES_USER, ES_PASS


application = Flask(import_name=__name__)
CORS(application)

@application.route(rule='/', methods=['GET', 'POST'])
def connection_page():
    return {'type': 'connections', 'reason': 'Success', 'data': None}

@application.route(rule='/reset-elasticsearch', methods=['POST'])
def reset_elasticsearch_page():
    try:
        loads(request.data)
    except:
        return {
            'type': 'storages', 
            'reason': 'BadRequest: Body must be JSON', 
            'data': None
        }, 400
    request_body = dict(request.get_json())
    elasticsearch_username = request_body.get('elasticsearchUsername')
    elasticsearch_password = request_body.get('elasticsearchPassword')
    if elasticsearch_username is None or elasticsearch_password is None:
        return {
            'type': 'storages', 
            'reason': 'BadRequest: Username or Password are required', 
            'data': None
        }, 400
    if elasticsearch_username != ES_USER or elasticsearch_password != ES_PASS:
        return {
            'type': 'storages', 
            'reason': 'Unauthorized: Incorrect Username or Password', 
            'data': None
        }, 401
    if load_rule_library() is False:
        return {
            'type': 'storages', 
            'reason': 'InternalServerError: Can\'t connect to Elasticsearch', 
            'data': None
        }, 500
    return {
        'type': 'storages', 
        'reason': 'Success', 
        'data': None
    }
    

@application.errorhandler(code_or_exception=404)
def not_found_page(error):
    return {
        'type': 'errors',
        'data': None,
        'reason': 'NotFound'
    }, 404

@application.errorhandler(code_or_exception=405)
def method_not_allowed_page(error):
    return {
        'type': 'errors',
        'data': None,
        'reason': 'MethodNotAllowed'
    }, 405

@application.errorhandler(code_or_exception=500)
def internal_server_error_page(error):
    return {
        'type': 'errors',
        'data': None,
        'reason': 'InternalServerError'
    }, 500


application.register_blueprint(blueprint=sqli_main_blueprint, url_prefix='/api')
application.register_blueprint(blueprint=xss_main_blueprint, url_prefix='/api')
application.register_blueprint(blueprint=fus_main_blueprint, url_prefix='/api')
application.register_blueprint(blueprint=rule_main_blueprint, url_prefix='/api')
application.register_blueprint(blueprint=yara_main_blueprint, url_prefix='/api')
application.register_blueprint(blueprint=result_main_blueprint, url_prefix='/api')
application.register_blueprint(blueprint=action_main_blueprint, url_prefix='/api')
application.register_blueprint(blueprint=resource_main_blueprint, url_prefix='/api')
application.register_blueprint(blueprint=wordlist_main_blueprint, url_prefix='/api')

application.register_blueprint(blueprint=sqli_analyzer_blueprint)
application.register_blueprint(blueprint=xss_analyzer_blueprint)
application.register_blueprint(blueprint=fus_analyzer_blueprint)

