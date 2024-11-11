from flask import Blueprint
from flask_restful import Api
from .list import ActionLists
from .create import ActionCreations
from .show import ActionDetails
from .update import ActionModifications
from .delete import ActionTerminations


action_operation_blueprint = Blueprint(name='action_operation_blueprint', import_name=__name__)

action_operation_api = Api(app=action_operation_blueprint)

action_operation_api.add_resource(ActionLists, '/list')
action_operation_api.add_resource(ActionCreations, '/create/<string:kind>')
action_operation_api.add_resource(ActionDetails, '/show/<string:id>')
action_operation_api.add_resource(ActionModifications, '/update/<string:id>')
action_operation_api.add_resource(ActionTerminations, '/delete/<string:id>')
