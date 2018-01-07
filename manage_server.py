#!/usr/bin/python
#encoding:utf-8

import sys
import time
from mul_thread_reverse import main

try:
    import schedule
except ImportError:
    sys.exit("无schedul模块,请安装 easy_install schedule")


if __name__ == "__main__":
    
    schedule.every(2).hours.do(main)   # 获取域名ip以及验证
    while True:
        schedule.run_pending()
        time.sleep(1)