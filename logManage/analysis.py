#!/usr/bin/python
# -*- coding:utf-8 -*-

from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
import ConfigParser
from utils import Query
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import cPickle
import re
import numpy

from storageEngine.elasticEngine import elasticManage
from utils import BaseFunction, Query


class TopAnalysis(object):
    def __init__(self):
        pass

    @classmethod
    def normal_analysis(self, n, index):
        """
        TOP n 日志分析-----正常分析，主要是列出Top n ip详情，以及ip对应的日志条数
        :param n: Top n
        :param index: elasticsearch 中的id
        :return:  返回top n 数据信息  {‘IP Address’:IP请求次数}
        """
        normal_top_result = {}
        elastic = elasticManage().search(index=index)  # elasticsearch 接口
        elastic.aggs.bucket('group_by_src_ip', 'terms',
                            field='ip_address.keyword', size=n)
        response = elastic.execute()
        print("--------"+index+"--------")
        for i in response.aggregations.group_by_src_ip.buckets:
            normal_top_result[i.key] = i.doc_count

        return normal_top_result

    @classmethod
    def threat_intelligence(self, ip):
        """
        威胁情报分析, 威胁情报平台采用OTX ，https://otx.alienvault.com/
        :return:
        """
        config = ConfigParser.ConfigParser()
        config.read('config/config.ini')
        otx_key = config.get('OTX_Token', 'key')
        otx = OTXv2(otx_key)
        otx_result = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        print(otx_result)


class SensitiveFileAnalysis(object):
    def __init__(self):
        pass

    @classmethod
    def backup_file_analysis(self, index):
        """
        备份文件检测
        :param index: elasticsearch 中的id
        :return:
        """

        # 读取config.ini配置文件中的rule
        config = ConfigParser.ConfigParser()
        config.read('config/config.ini')
        rule = config.get('backup_file_analysis', 'rule')

        elastic = Query(ip="127.0.0.1", port=9200)
        result = elastic.query(index=index, data=rule)

        BaseFunction.result_dispose(result, index=index, query=rule, none_message="========备份文件分析未检测到威胁========")


class SecureAnalysis(object):
    def __init__(self):
        pass

    @classmethod
    def sql_analysis(cls):
        query_data = BaseFunction.join_query(keyword="URI", rule_name="sql_analysis")
        result = Query().query(None, data=query_data)
        BaseFunction.result_dispose(result, index=None, query=query_data, none_message="========SQL注入分析未检测到威胁========")

    @classmethod
    def http_method_analysis(cls):
        query_data = BaseFunction.join_query(keyword="method", rule_name="http_method_analysis")
        result = Query().query(index=None, data=query_data)
        BaseFunction.result_dispose(result, index=None, query=query_data, none_message="========http method 分析未检测到威胁(无不安全的http请求方法)========")

    @classmethod
    def web_command_attack_analysis(cls):
        query_data = BaseFunction.join_query(keyword="URI", rule_name="common_web_analysis")
        result = Query().query(None, data=query_data)
        BaseFunction.result_dispose(result, index=None, query=query_data, none_message="========Web 通用攻击分析未检测到威胁========")

    @classmethod
    def xss_analysis(cls):
        query_data = BaseFunction.join_query(keyword="URI" ,rule_name="xss_analysis")
        result = Query().query(None, data=query_data)
        BaseFunction.result_dispose(result, index=None, query=query_data, none_message="========XSS攻击分析未检测到威胁========")


class ML_Analysis(object):
    """
    机器学习分析检测模块
    """
    def __init__(self):
        pass

    def get_len(self, url):
        return len(url)

    def get_url_count(self, url):
        if re.search('(http://)|(https://)', url, re.IGNORECASE):
            return 1
        else:
            return 0

    def get_evil_char(self, url):
        return len(re.findall("[<>,\'\"/]", url, re.IGNORECASE))

    def get_evil_word(self, url):
        return len(re.findall(
            "(alert)|(script=)(%3c)|(%3e)|(%20)|(onerror)|(onload)|(eval)|(src=)|(prompt)|(onmouseon)|(onmouseover)|(/\*)|(\*/)",
            url, re.IGNORECASE))

    def get_feature(self, url):
        return [self.get_len(url), self.get_url_count(url), self.get_evil_char(url), self.get_evil_word(url)]

    def xss_analysis(self):
        urls = []
        clf = None
        data = """
        {
          "aggs": {
            "group_by_uri": {
              "terms": {
                "field": "URI.keyword",
                "size": 2147483647
              }
            }
          },
          "size": 0
        }
        """
        result = Query().query(index=None, data=data)   #返回所有去重之后的URI列表
        for result_message in result.get("aggregations").get("group_by_uri").get("buckets"):
            urls.append(result_message.get('key')) #得到elasticsearch中所有的经过去重后的URI信息

        with open("ML/xss_ML.pkl", 'rb') as f:
            clf = cPickle.load(f)

        for url in urls:
            result = clf.predict(numpy.mat(self.get_feature(url=url)))
            if result[0] == 1:
                data = """
                {{
                  "query": {{
                    "match": {{
                      "URI": "{0}"
                    }}
                  }},
                  "aggs": {{
                    "group_by_ip_address": {{
                      "terms": {{
                        "field": "ip_address.keyword",
                        "size": 2147483647
                      }}
                    }}
                  }}
                }}
                """.format(url)    #根据URI反查IP地址
                result = Query().query(index=None, data=data)
                buckets = result.get("aggregations").get("group_by_ip_address").get("buckets")
                if len(buckets) > 20:
                    print(url+"  "),
                    print("反查其IP数为{},可能为误报".format(len(buckets)))
                else:
                    print(url)
                    data = """
                                    {{
                                      "query": {{
                                        "match": {{
                                          "URI": "{0}"
                                        }}
                                      }},
                                      "aggs": {{
                                        "group_by_ip_address": {{
                                          "terms": {{
                                            "field": "ip_address.keyword",
                                            "size": 2147483647
                                          }}
                                        }}
                                      }}
                                    }}
                                    """.format(url)  # 根据URI反查IP地址
                    result = Query().query(index=None, data=data)
                    buckets = result.get("aggregations").get("group_by_ip_address").get("buckets")
                    print("产生此URL的ip地址为：")
                    for bucket in buckets:
                        print(bucket.get("key"))


