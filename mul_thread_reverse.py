#!/usr/bin/python
# encoding:utf-8
"""
用来获取whois域名的IP地址
"""

import dns.resolver
from db_manage import MySQL
import socket


import time
import threading
from Queue import Queue
from threading import Thread
from datetime import datetime


num_thread = 10      # 线程数量
queue = Queue()     # 任务队列，存储sql
lock = threading.Lock()
current_ip_port = {}


def connect_port(ip):
    """
    使用socket与ip的43端口进行连接
    参数
        ip: string 需要验证的ip
    返回值
        True/False: boolean 是否可连接
    """
    port = 43  # whois服务器端口号
    s = socket.socket()
    s.settimeout(5)
    socket_no = s.connect_ex((ip, port),)
    s.close()
    if socket_no == 0:  # 连接成功
        return True
    else:
        return False


def get_port_flag(ips):
    """
    批量验证端口是否开放,并生成标记位
    """
    available_flag = ''
    for ip in ips:
        if connect_port(ip):
            available_flag += '1'
        else:
            if connect_port(ip):  # 重复验证一次
                available_flag += '1'
            else:
                available_flag += '0'
    return available_flag


def judege_ips_equal(domain_latest_ips,source_ips):
    """判断两个ip列表是否相同
    参数
        source_ips: list 数据库原有IP,不为空
        domain_latest_ips: list 域名最新解析的ip，不为空
    返回值
        True/False: boolean 两个列表是否相同
    """
    return set(domain_latest_ips).issubset(set(source_ips))


def merge_ips(source_ips,domain_latest_ips):
    
    return list(set(source_ips+domain_latest_ips))


def get_svr_from_db():
    """
    从数据库中获取已有whois服务器地址和已有的IP地址
    :return:
    """
    db = MySQL()
    sql = 'SELECT svr_name,ip FROM whois_srvip'
    db.query(sql)
    svr_ips = db.fetchAllRows()
    db.close()
    return list(svr_ips)


def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except:
        return False




def domain2ip(domain):
    """
    域名解析为IP列表
    参数
        domain: string 待解析的域名
    
    返回值
        ips: list 域名解析后的ip列表
    """
    if valid_ip(domain):   # 如果whois服务器为IP地址，则直接返回
        return [domain]
    ips = []
    res = dns.resolver.Resolver()
    res.nameservers = ['8.8.8.8','8.8.4.4','114.114.114.114','223.5.5.5','223.6.6.6']
    
    try:
        domain_ip = res.query(domain,'A')
        for i in domain_ip:
            ips.append(i.address)
    except:
        ips = []
    return ips

                
def get_latest_svr_ips(domain_latest_ips,source_ips):
    """
    新获取的IP地址和原来已有的IP地址
    :param domain_latest_ips: 新获取的IP地址
    :param source_ips: 已有的IP地址
    :return:
    """
    if source_ips is None:
        return domain_latest_ips
    if not domain_latest_ips:
        return source_ips.split(',')
    if judege_ips_equal(domain_latest_ips,source_ips.split(',')):
        return source_ips.split(',')
    else:
        return merge_ips(domain_latest_ips,source_ips.split(','))



def create_queue():
    """创建队列"""
    svr_addr = get_svr_from_db()  # 得到要查询的列表
    for srv,addr in svr_addr:
        queue.put((srv,addr))


def get_svr_ip():
    """
    获取服务器的IP地址，并与已有ip比对,最后更新数据库
    """

    while 1:
        srv, ip = queue.get()
        ips = domain2ip(srv)
        latest_ips = get_latest_svr_ips(ips, ip)
        # lock.acquire()
        if latest_ips:
            key = current_ip_port.get( ','.join(sorted(latest_ips)))
            if key:
                print "重复"
                port_flag = key
            else:
                port_flag = get_port_flag(latest_ips)
                lock.acquire()
                current_ip_port[','.join(sorted(latest_ips))] = port_flag
                lock.release()
            print srv, str(latest_ips), port_flag
            update_data(latest_ips, port_flag, srv)

        # lock.release()  # 解锁
        queue.task_done()
        time.sleep(1)  # 去掉偶尔会出现错误

def update_data(ip,port,srv):
    """
    更新数据库
    :param ip:
    :param port:
    :param srv:
    :return:
    """
    db = MySQL()
    sql = 'UPDATE whois_srvip SET ip="%s",port_available="%s" WHERE svr_name="%s"'
    db.update(sql % (','.join(ip), port, srv))
    db.close()

def main():
    print str(datetime.now()), '开始解析whois服务器域名'
    global current_ip_port
    current_ip_port = {}
    create_queue()
    for q in range(num_thread):  # 开始任务
        worker = Thread(target=get_svr_ip)
        worker.setDaemon(True)
        worker.start()
    queue.join()
    print str(datetime.now()), '结束解析whois服务器域名'


if __name__== '__main__':
    main()