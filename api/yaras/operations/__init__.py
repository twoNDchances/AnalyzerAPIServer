from flask import Blueprint
from flask_restful import Api
from .create import YARARuleCreations
from .list import YARARuleLists



yara_operation_blueprint = Blueprint(name='yara_operation_blueprint', import_name=__name__)
yara_operation_api = Api(app=yara_operation_blueprint)

yara_operation_api.add_resource(YARARuleCreations, '/create')
yara_operation_api.add_resource(YARARuleLists, '/list')
