#!/usr/bin/python
# -*- coding:utf-8 -*-

import ConfigParser
import os

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
import elasticsearch.helpers

from utils import Query

class elasticManage(object):
    def __init__(self):
        self.es = Elasticsearch("127.0.0.1:9200", timeout=30)

    def connect_elastic(self):
        """
        连接elasticsearch
        :return: 返回elasticsearch连接
        """
        return self.es

    def search(self, index, **kwargs):
        """
        elasticsearch search 接口
        :return:返回elasticsearch search 接口
        """
        return Search(using=self.es, index=index, **kwargs)

    def saveMessage(self, messages, index):
        """

        :param messages:日志归一化数组
        :param index: elasticsearch
        :return:
        """
        tmp = []
        for message in messages:
            log_row = {
                "@timestamp":message.get('date_day')+" "+message.get('date_time'),
            }
            for key in message.keys():
                log_row[key] = message.get(key)
                if key == "URI":
                    log_row[key] = message.get(key).lower()

            tmp.append(log_row)

        actions = [
            {
                '_index': index,
                '_type': "web",
                '_source': d
            }
            for d in tmp
        ]
        elasticsearch.helpers.bulk(self.es, actions)


class ElasticOptimization(object):
    """
    elasticsearch 上传数据优化类
    """
    def __init__(self):
        pass

    @staticmethod
    def start_optimization(index):
        """
        优化elasticsearch setting ，加快数据上传速度
        :param index: elasticsearch index
        :return:
        """
        print("优化任务开启.........")
        config = ConfigParser.ConfigParser()
        config.read(os.path.join(os.path.dirname(os.path.dirname(__file__)),'config/config.ini'))
        max_bytes_per_sec = config.get("Optimization_Config", "max_bytes_per_sec")
        Query().setting(index=index, data='"persistent" : {{"indices.store.throttle.max_bytes_per_sec" : "{0}mb"}}'.format(max_bytes_per_sec))

        Query().setting(index=index, data='"transient" : {"indices.store.throttle.type" : "none" }')

        Query().setting(index=index, data='{"index": {"refresh_interval": "-1"}}')

    @staticmethod
    def restore_settings(index):
        """
        恢复elasticsearch setting 更改，方便数据分析查询
        :param index: elasticsearch index
        :return:
        """

        print("还原配置.........")
        Query().setting(index=index, data='"persistent" : {{"indices.store.throttle.max_bytes_per_sec" : "20mb"}}')

        Query().setting(index=index, data='"transient" : {"indices.store.throttle.type" : "merge" }')

        Query().setting(index=index, data='{"index": {"refresh_interval": "1s"}}')
