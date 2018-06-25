#!/usr/bin/python
# -*- coding:utf-8 -*-

from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
import ConfigParser
from utils import Query
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

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
