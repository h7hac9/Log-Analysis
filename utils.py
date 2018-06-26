#!/usr/bin/python
# -*- coding:utf-8 -*-

import requests
import json
import ConfigParser


class Query(object):
    def __init__(self, ip="127.0.0.1", port=9200):
        """

        :param ip: elasticsearch ip address
        :param port: elasticsearch port
        """
        self.ip = ip
        self.port = port

    def query(self, index, data):
        """

        :param index:  elasricsearch id
        :param data:   请求主体
        :return:
        """
        if index is None:
            target_uri = "http://{}:{}/_search".format(self.ip, self.port)
        else:
            target_uri = "http://{}:{}/{}/_search".format(self.ip,self.port,index)
        response = requests.post(url=target_uri, data=data, headers={"Content-Type": "application/json"})

        return json.loads(response.text)

    def delete(self, index):
        """

        :param index: elasricsearch id
        :return:
        """
        target_uri = "http://{}:{}/{}".format(self.ip,self.port,index)
        response = requests.delete(url=target_uri, headers={"Content-Type": "application/json"})

        print(json.loads(response.text))

    def setting(self, index, data):
        target_uri = "http://{}:{}/{}/_settings".format(self.ip, self.port, index)
        response = requests.put(url=target_uri, data=data, headers={"Content-Type": "application/json"})

    def put(self, index, data):
        target_uri = "http://{}:{}/{}/".format(self.ip, self.port, index)
        response = requests.put(url=target_uri, data=data, headers={"Content-Type": "application/json"})


class BaseFunction(object):
    """
    elasticsearch 查询基础功能类
    """
    def __init__(self):
        pass

    @staticmethod
    def join_query(keyword, rule_name):
        """
        拼接查询语句功能
        :param keyword: elasticsearch 中要查询的keyword字段
        :param rule_name: 规则名称
        :return:返回查询结果
        """
        config = ConfigParser.ConfigParser()
        config.read("config/config.ini")
        rule = config.get(section="{}".format(rule_name), option="rule")
        rule_list = rule.split('|')
        query = ""   #最后的查询语句中should字段中的内容

        for rule in rule_list:
            query = query + '{{"wildcard": {{"{0}.keyword": "*{1}*"}}}},'.format(keyword, rule)

        query_message = '{{"query": {{"bool": {{"should": [{0}]}}}}}}'.format(query.rstrip(','))

        return query_message


    @staticmethod
    def result_dispose(result, index, query, none_message):
        """
        对elasticssearch传递的结果进行处理
        :param result: elasticsearch 结果
        :param none_message: 当elasticsearch结果为空时显示的提示消息
        :param index : elasticsearch index
        :param query : 查询语句
        :return:
        """
        elastic = Query(ip="127.0.0.1", port=9200)
        result_ip = []  # 威胁IP列表

        if result.get('hits').get('total') != 0:
            if result.get('hits').get('total') <= 5:
                for i in result.get('hits').get('hits'):
                    result_ip.append(i.get('_source').get('ip_address'))

            elif result.get('hits').get('total') > 5:
                result = elastic.query(
                    index=index,
                    data=query.rstrip('}')+'}},"size":%d}' % (result.get('hits').get('total')))

                for i in result.get('hits').get('hits'):
                    result_ip.append(i.get('_source').get('ip_address'))

            for ip in list(set(result_ip)):
                print(ip + "危险访问操作")
                for i in result.get('hits').get('hits'):
                    if i.get('_source').get('ip_address') == ip:
                        print('【-】 ' + i.get('_source').get('URI') + " " + i.get('_source').get('domain') +
                              " " + i.get('_source').get('method') + " " + i.get('_source').get('statuscode'))
        else:
            print(none_message)

