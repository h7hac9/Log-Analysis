#!/usr/bin/python
# -*- coding:utf-8 -*-

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
import elasticsearch.helpers


class elasticManage(object):
    def __init__(self):
        self.es = Elasticsearch("127.0.0.1:9200")

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