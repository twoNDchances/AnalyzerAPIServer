from flask import Blueprint
from flask_restful import Api
from .list import SQLInjectionRuleLists
from .create import SQLInjectionRuleCreations
from .show import SQLInjectionRuleDetails
from .update import SQLInjectionRuleModifications
from .delete import SQLInjectionRuleTerminations


sqli_operation_blueprint = Blueprint(name='sqli_operation_blueprint', import_name=__name__)
sqli_operation_api = Api(app=sqli_operation_blueprint)

sqli_operation_api.add_resource(SQLInjectionRuleLists, '/list')
sqli_operation_api.add_resource(SQLInjectionRuleCreations, '/create')
sqli_operation_api.add_resource(SQLInjectionRuleDetails, '/show/<string:id>')
sqli_operation_api.add_resource(SQLInjectionRuleModifications, '/update/<string:id>')
sqli_operation_api.add_resource(SQLInjectionRuleTerminations, '/delete/<string:id>')
