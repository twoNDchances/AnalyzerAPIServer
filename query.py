from elasticsearch import Elasticsearch
from gather import ES_HOST, ES_USER, ES_PASS
from json import dumps


es = Elasticsearch(hosts=ES_HOST, basic_auth=(ES_USER, ES_PASS))


if es.ping() is False:
    print('Fail to connect to Elasticsearch')
    
else:
    # response = es.indices.get(index='analyzer-rules')
    # print(response)
    # response = es.search(index='analyzer-sqlis', body={"query": {"match_all": {}}})
    # print(dumps(response.raw))
    # print(response.raw['hits']['hits'].__len__())
    # for data in response.raw['hits']['hits']:
    #     print(dumps(data['_source']))
    # print(dumps(response['hits']['hits']))
    # index_name = "analyzer-rules"
    # field_name = "rule_type"  # Trường bạn muốn lấy các giá trị duy nhất
    # response = es.search(index='analyzer-sqlis', query={"match_phrase": {"rule_name": 'my-rule-4'}}, size=1000000000)
    # for data in response.raw['hits']['hits']:
    #     print(dumps(data))
    # print(response['hits']['hits'])
    # response = es.search(
    #     index=index_name,
    #     body={
    #         "aggs":{
    #             "unique_names": {
    #                 "terms": {
    #                     "field": "rule_type.keyword"
    #                 }
    #             }
    #         },
    #         "_source": False
    #     },
    # )

    # for i in response.raw['aggregations']['unique_names']['buckets']:
    #     print(i['key'])
    # response = es.count(index=index_name)
    # print(response)
    # response = es.search(
    #             index='analyzer-rules',
    #             body={
    #                 "aggs":{
    #                     "unique_names": {
    #                         "terms": {
    #                             "field": "rule_type.keyword"
    #                         }
    #                     }
    #                 },
    #                 "_source": False
    #             },
    #             size=1000000000
    #         )
    # print(response)
    response = es.get(index='analyzer-actions', id='qTQkHJMBxlZWHj5Pm6IE')
    # response = es.update(index='analyzer-sqlis', id='WzTmGpMBxlZWHj5PhaIS', doc={
    #     'rule_name': 'test-2'
    # })
    print(response.raw)