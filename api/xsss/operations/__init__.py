from flask import Blueprint
from flask_restful import Api
from .list import CrossSiteScriptingRuleLists
from .create import CrossSiteScriptingRuleCreations
from .show import CrossSiteScriptingRuleDetails
from .update import CrossSiteScriptingRuleModifications
from .delete import CrossSiteScriptingRuleTerminations


xss_operation_blueprint = Blueprint(name='xss_operation_blueprint', import_name=__name__)
xss_operation_api = Api(app=xss_operation_blueprint)

xss_operation_api.add_resource(CrossSiteScriptingRuleLists, '/list')
xss_operation_api.add_resource(CrossSiteScriptingRuleCreations, '/create')
xss_operation_api.add_resource(CrossSiteScriptingRuleDetails, '/show/<string:id>')
xss_operation_api.add_resource(CrossSiteScriptingRuleModifications, '/update/<string:id>')
xss_operation_api.add_resource(CrossSiteScriptingRuleTerminations, '/delete/<string:id>')
