from flask import Flask, jsonify
from flask_cors import CORS

from .rules import rule_main_blueprint

from .sqlis import sqli_main_blueprint
from .sqlis import sqli_analyzer_blueprint

from .xsss import xss_main_blueprint
from .xsss import xss_analyzer_blueprint

from .fus import fus_main_blueprint
from .fus import fus_analyzer_blueprint

from .yaras import yara_main_blueprint

from .actions import action_main_blueprint


application = Flask(import_name=__name__)
CORS(application)

@application.route(rule='/', methods=['GET'])
def connection_page():
    response = {'type': 'connections', 'reason': 'Success', 'data': None}
    return jsonify(response), 200


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
application.register_blueprint(blueprint=action_main_blueprint, url_prefix='/api')

application.register_blueprint(blueprint=sqli_analyzer_blueprint)
application.register_blueprint(blueprint=xss_analyzer_blueprint)
application.register_blueprint(blueprint=fus_analyzer_blueprint)

