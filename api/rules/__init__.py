from flask import Blueprint
from .operations import rule_operation_blueprint


rule_main_blueprint = Blueprint(name='rule_main_blueprint', import_name=__name__)

rule_main_blueprint.register_blueprint(blueprint=rule_operation_blueprint, url_prefix='/rules')