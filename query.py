from elasticsearch import Elasticsearch
from gather import ES_HOST, ES_USER, ES_PASS
from json import dumps
import yara


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
    # response = es.get(index='analyzer-yaras', id='ljtJH5MBWtteEDjX_aGt')
    # print(response.raw['_source'])
    # response = es.update(index='analyzer-sqlis', id='WzTmGpMBxlZWHj5PhaIS', doc={
    #     'rule_name': 'test-2'
    # })
    # response = es.search(index='analyzer-yaras', query={'match_all': {}}, size=100000)
    rule = yara.compile(source='rule php_dns  : webshell{ meta: description = "Laudanum Injector Tools - file dns.php" author = "Florian Roth" reference = "http://laudanum.inguardians.com/" date = "2015-06-22" hash = "01d5d16d876c55d77e094ce2b9c237de43b21a16" strings: $s1 = "$query = isset($_POST[\'query\']) ? $_POST[\'query\'] : \'\';" fullword ascii /* PEStudio Blacklist: strings */ $s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii /* PEStudio Blacklist: strings */ $s3 = "if ($_SERVER[\\"REMOTE_ADDR\\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */ $s4 = "foreach (array_keys($types) as $t) {" fullword ascii condition: filesize < 15KB and all of them }  rule WEB_INF_web  : webshell{ meta: description = "Laudanum Injector Tools - file web.xml" author = "Florian Roth" reference = "http://laudanum.inguardians.com/" date = "2015-06-22" hash = "0251baed0a16c451f9d67dddce04a45dc26cb4a3" strings: $s1 = "<servlet-name>Command</servlet-name>" fullword ascii /* PEStudio Blacklist: strings */ $s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii condition: $s1 or $s2 }  rule jsp_cmd : webshell { meta: description = "Laudanum Injector Tools - file cmd.war" author = "Florian Roth" reference = "http://laudanum.inguardians.com/" date = "2015-06-22" hash = "55e4c3dc00cfab7ac16e7cfb53c11b0c01c16d3d" strings: $s0 = "cmd.jsp}" fullword ascii $s1 = "cmd.jspPK" fullword ascii $s2 = "WEB-INF/web.xml" fullword ascii /* Goodware String - occured 1 times */ $s3 = "WEB-INF/web.xmlPK" fullword ascii /* Goodware String - occured 1 times */ $s4 = "META-INF/MANIFEST.MF" fullword ascii /* Goodware String - occured 12 times */ condition: uint16(0) == 0x4b50 and filesize < 2KB and all of them }')
    match = rule.match(data='<jsp-file>/cmd.jsp</jsp-file>')
    print(match)