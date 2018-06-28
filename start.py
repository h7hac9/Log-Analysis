#!/usr/bin/python
# -*- coding:utf-8 -*-

import os
import gzip
import sys
import ConfigParser
import time

from logManage import format, analysis
from storageEngine import elasticEngine
from utils import Query


def main():
    read_log_file()  # 读取日志文件并存储到elasticsearch
    print("【!】日志上传操作任务完成........")
    print("【+】日志分析操作任务开启........")
    top_analysis = analysis.TopAnalysis()

    threat_intelligence_check(top_analysis)  #威胁情报分析检测

    config = ConfigParser.ConfigParser()
    config.read(r'config/task.ini')
    elasticsearch_id = config.get('elasticsearch_id', 'id')  # 读取配置文件中的id信息
    for i in elasticsearch_id.split(','):
        analysis.SensitiveFileAnalysis.backup_file_analysis(index=i)  #备份文件检测

    print("【+】SQL注入日志检测任务开启........")
    analysis.SecureAnalysis.sql_analysis()

    print("【+】Http method 日志检测任务开启........")
    analysis.SecureAnalysis.http_method_analysis()

    print("【+】Web 通用攻击 日志检测任务开启........")
    analysis.SecureAnalysis.web_command_attack_analysis()

    print("【+】XSS攻击 日志检测任务开启........")
    analysis.SecureAnalysis.xss_analysis()

    print("日志分析结束，是否删除elasticsearch留存的数据(Y/N):")
    print("tips:正常情况下是需要全部清空elasticsearch中的日志的")
    choose = raw_input("请输入：")
    if choose=="Y" or choose=="y":
        task_end()
    else:
        print("[*]日志分析结束，程序正常退出........")


def upload_start(index):
    """
    关闭刷新，加快elasticsearch导入数据速度
    :param index: elastic search id
    :return:
    """
    data = '{"index": {"refresh_interval": "-1"}}'
    Query().setting(index=index, data=data)


def upload_stop(index):
    data = '{"index": {"refresh_interval": "1s"}}'
    Query().setting(index=index, data=data)


def task_end():
    config = ConfigParser.ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__),'config/task.ini'))
    elasticsearch_id = config.get("elasticsearch_id", 'id')
    for id in elasticsearch_id.split(','):
        Query().delete(index=id)
    os.remove("config/task.ini")


def threat_intelligence_check(top_analysis):
    normal_top_result = top_analysis_check(top_analysis)
    print("【+】OTX IP威胁情报检测任务开始........")

    for result in normal_top_result:
        for ip_address in result.keys():
            top_analysis.threat_intelligence(ip_address)


def top_analysis_check(top_analysis):

    normal_top_result = []

    config = ConfigParser.ConfigParser()
    config.read(r'config/task.ini')

    elasticsearch_id = config.get('elasticsearch_id', 'id')  # 读取配置文件中的id信息
    for i in elasticsearch_id.split(','):
        result = top_analysis.normal_analysis(n=5, index=i)
        normal_top_result.append(result)
        print(result)
    print("【!】Top 分析结束........")
    return normal_top_result


def read_log_file():
    id = ""  # elasticsearch id列表
    config = ConfigParser.ConfigParser()
    config.add_section("elasticsearch_id")

    for root, path, files in os.walk('log'):
        for file in files:
            id = id + file.split('-')[2].split('.')[0]+","
            Query().put(index=file.split('-')[2].split('.')[0], data="")   #创建elasticsearch id
            upload_start(index=file.split('-')[2].split('.')[0])
            line_number = 0
            size = 0
            with gzip.open(os.path.join(root, file), 'r') as f:
                while f.readline() is not None:
                    line_number += 1
            
            print("【!】文件读取成功........")

            with gzip.open(os.path.join(root, file), 'r') as f:
                logformat = []
                logline = f.readline()
                print("【+】{} 开始上传........".format(file))
                while logline != "":
                    for i in xrange(100000):
                        if logline != "":
                            loglinemanage = format.LogClass(log=logline)
                            logformat.append(loglinemanage.formatting())
                            logline = f.readline()
                    elasticE = elasticEngine.elasticManage()
                    elasticE.saveMessage(logformat, file.split('-')[2].split('.')[0])
                    logformat = []

                    size = size + 100000
                    view_bar(size, line_number)
            upload_stop(index=file.split('-')[2].split('.')[0])
            time.sleep(5)
            print("->")

        print("【!】写入配置文件........")
        config.set('elasticsearch_id', 'id', id.rstrip(','))
        config.write(open('config/task.ini', 'w'))
        print("【!】配置文件写入成功........【task.ini】")


def view_bar(num, total):
    rate = float(num) / total
    rate_num = int(rate * 100)+1
    r = '\r[%s%s]%d%%' % ("#"*rate_num, " "*(100-rate_num), rate_num, )
    sys.stdout.write(r)
    sys.stdout.flush()


if __name__ == '__main__':
    main()
