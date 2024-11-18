from flask import Blueprint
from .operations import resource_operation_blueprint

resource_main_blueprint = Blueprint(name='resources_main_blueprint', import_name=__name__)

resource_main_blueprint.register_blueprint(blueprint=resource_operation_blueprint, url_prefix='/resources')
