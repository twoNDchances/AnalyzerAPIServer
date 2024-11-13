from elasticsearch import Elasticsearch
from gather import ES_HOST, ES_USER, ES_PASS, ES_MAX_RESULT


response_elasticsearch = Elasticsearch(hosts=ES_HOST, basic_auth=(ES_USER, ES_PASS))

