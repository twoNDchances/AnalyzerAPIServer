from os import getenv
from api import application
from gather import BACKEND_HOST, BACKEND_PORT
from setup import check_elasticsearch

if __name__ == '__main__':
    environment_variables = {
        'ES_HOST': 'http://localhost:9200',
        'ES_USER': 'elastic',
        'ES_PASS': 'elastic',
        'ES_MAX_RESULT': 1000000000,
        'BACKEND_HOST': '0.0.0.0',
        'BACKEND_PORT': 9947,
        'BACKEND_DEFAULT_WEBHOOK': 'http://localhost'
    }
    config = {variable: getenv(variable, default) for variable, default in environment_variables.items()}
    print('========== Environment Variable Configurations ==========')
    for variable, value in config.items():
        if variable == 'ES_PASS':
            print(f'{variable} = {"*" * value.__len__()}')
        else:
            print(f'{variable} = {value}')
    print('=========================================================', end='\n\n')
    print('================ Elasticsearch Checking =================')
    check_elasticsearch()
    print('=========================================================', end='\n\n')
    application.run(debug=True, host=BACKEND_HOST, port=BACKEND_PORT)
