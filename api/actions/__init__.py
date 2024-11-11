from flask import Blueprint
from .operations import action_operation_blueprint


action_main_blueprint = Blueprint(name='action_main_blueprint', import_name=__name__)

action_main_blueprint.register_blueprint(blueprint=action_operation_blueprint, url_prefix='/actions')
