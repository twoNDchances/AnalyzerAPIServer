from flask import Blueprint
from .operations import yara_operation_blueprint


yara_main_blueprint = Blueprint(name='yara_main_blueprint', import_name=__name__)

yara_main_blueprint.register_blueprint(blueprint=yara_operation_blueprint, url_prefix='/yaras')
