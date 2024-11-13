from flask import Blueprint
from flask_restful import Api
from .create import FileUploadRuleCreations
from .list import FileUploadRuleLists


fus_operation_blueprint = Blueprint(name='fus_operation_blueprint', import_name=__name__)
fus_operation_api = Api(app=fus_operation_blueprint)

fus_operation_api.add_resource(FileUploadRuleCreations, '/create')
fus_operation_api.add_resource(FileUploadRuleLists, '/list')