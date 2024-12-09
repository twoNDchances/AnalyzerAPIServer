from flask import Blueprint
from flask_restful import Api
from .list import ResultLists
from .show import ErrorLogsManifests
from .delete import ErrorlogsTerminations


results_operation_blueprint = Blueprint(name='results_operation_blueprint', import_name=__name__)
results_operation_api = Api(app=results_operation_blueprint)

results_operation_api.add_resource(ResultLists, '/list')
results_operation_api.add_resource(ErrorLogsManifests, '/show/<string:rule_name>')
results_operation_api.add_resource(ErrorlogsTerminations, '/empty-errorlogs/<string:rule_name>')
