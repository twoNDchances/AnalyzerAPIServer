from flask import request
from flask_restful import Resource
from ...storage import response_elasticsearch


class ActionLists(Resource):
    def get(self):
        if response_elasticsearch.ping() is False:
            return {
                'type': 'actions',
                'data': None,
                'reason': 'InternalServerError: Can\'t connect to Elasticsearch'
            }, 500
        if response_elasticsearch.count(index='analyzer-actions').raw['count'] == 0:
            return {
                'type': 'actions',
                'data': None,
                'reason': 'NotFound: Not found any record in Actions'
            }, 404
        if request.args.get('actionName') is not None:
            action_names = response_elasticsearch.search(
                    index='analyzer-actions',
                    body={
                        "aggs":{
                            "unique_names": {
                                "terms": {
                                    "field": "action_name.keyword"
                                }
                            }
                        },
                        "_source": False
                    },
                    size=1000000000
                )
            return {
                'type': 'actions',
                'data': [action_name['key'] for action_name in action_names.raw['aggregations']['unique_names']['buckets']],
                'reason': 'Success'
            }
        actions = response_elasticsearch.search(index='analyzer-actions', body={"query": {"match_all": {}}}, size=1000000000)
        return {
            'type': 'action',
            'data': [{
                'id': action['_id'],
                'action_name': action['_source']['action_name'],
                'action_type': action['_source']['action_type'],
                'action_configuration': action['_source']['action_configuration']
            } for action in actions.raw['hits']['hits']],
            'reason': 'Success'
        }
