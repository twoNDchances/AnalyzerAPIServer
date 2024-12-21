from flask import Blueprint
from flask_restful import Api
from .create import WordlistCreations
from .list import WordlistLists, WordlistNames, WordlistRelatedLists
from .show import WordlistShow
from .update import WordlistModifications
from .delete import WordlistTerminations


wordlist_operation_blueprint = Blueprint(name='wordlist_operation_blueprint', import_name=__name__)
wordlist_operation_api = Api(app=wordlist_operation_blueprint)

wordlist_operation_api.add_resource(WordlistCreations, '/create')
wordlist_operation_api.add_resource(WordlistLists, '/list')
wordlist_operation_api.add_resource(WordlistNames, '/list-names')
wordlist_operation_api.add_resource(WordlistRelatedLists, '/list-related/<string:wordlist_name>')
wordlist_operation_api.add_resource(WordlistShow, '/show/<string:wordlist_name>')
wordlist_operation_api.add_resource(WordlistModifications, '/update/<string:wordlist_name>')
wordlist_operation_api.add_resource(WordlistTerminations, '/delete/<string:wordlist_name>')
