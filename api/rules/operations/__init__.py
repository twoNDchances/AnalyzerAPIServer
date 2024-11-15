from flask import Blueprint
from flask_restful import Api
from .list import RuleLibraries
from .create import RuleInheritances
from .show import RuleManifests
from .update import RuleModifications
from .delete import RuleTerminations


rule_operation_blueprint = Blueprint(name='rule_operation_blueprint', import_name=__name__)
rule_operation_api = Api(app=rule_operation_blueprint)

rule_operation_api.add_resource(RuleLibraries, '/rule-library')
rule_operation_api.add_resource(RuleInheritances, '/rule-inheritance')
rule_operation_api.add_resource(RuleManifests, '/rule-manifest/<string:id>')
rule_operation_api.add_resource(RuleModifications, '/rule-modification/<string:id>')
rule_operation_api.add_resource(RuleTerminations, '/rule-termination/<string:id>')
