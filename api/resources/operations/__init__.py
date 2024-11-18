from flask import Blueprint
from flask_restful import Api
from .create import ResourceCreations


resource_operation_blueprint = Blueprint(name='resource_operation_blueprint', import_name=__name__)
resource_operation_api = Api(app=resource_operation_blueprint)

resource_operation_api.add_resource(ResourceCreations, '/create')
