from flask import Blueprint
from .operations import results_operation_blueprint


result_main_blueprint = Blueprint(name='result_main_blueprint', import_name=__name__)

result_main_blueprint.register_blueprint(blueprint=results_operation_blueprint, url_prefix='/results')
