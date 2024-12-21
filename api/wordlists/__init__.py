from flask import Blueprint
from .operations import wordlist_operation_blueprint


wordlist_main_blueprint = Blueprint(name='wordlist_main_blueprint', import_name=__name__)

wordlist_main_blueprint.register_blueprint(blueprint=wordlist_operation_blueprint, url_prefix='/wordlists')
