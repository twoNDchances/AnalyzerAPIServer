from flask import Blueprint
from flask_restful import Api
from .list import ResultLists
from .show import ResultManifests


results_operation_blueprint = Blueprint(name='results_operation_blueprint', import_name=__name__)
results_operation_api = Api(app=results_operation_blueprint)

results_operation_api.add_resource(ResultLists, '/list')
results_operation_api.add_resource(ResultManifests, '/show/<string:id>')
