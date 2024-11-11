from api import application
from gather import BACKEND_HOST, BACKEND_PORT, BACKEND_YAML


if __name__ == '__main__':
    application.run(debug=True, host=BACKEND_HOST, port=BACKEND_PORT)
