#!/usr/bin/python
# -*- coding:utf-8 -*-

import ConfigParser
import re
import os


class LogClass(object):
    def __init__(self, log):
        self.log = log
        self.log_format_config = ConfigParser.ConfigParser()
        self.log_format_config.read(os.path.join(os.path.dirname(__file__),'logformat.ini'))

    def formatting(self):
        configSections = self.log_format_config.sections()
        for i in configSections:
            regular = self.log_format_config.get(i, 'log_format')  # 正则表达式
            try:
                r = re.match(regular, self.log)
                result = r.groupdict()
            except Exception as e:
                result = None

        if result is not None:
            return result
        else:
            print("ERROR")
