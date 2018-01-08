# 域名WHOIS服务器的IP地址和端口验证系统

## 功能包括
1. 实现域名WHOIS服务器地址解析为IP地址
2. 验证WHOIS服务器的43端口状态

## 安装包
* dnspython (pip install dnspython)

## 验证原理
与目标IP地址的43端口建立TCP连接，连接成功，表示开放

## 运行程序

修改db_manage.py中的数据库配置名称，选择要更新的数据库

1. 直接运行，只更新一次 
 `python reverse1.py `  
2. 多线程
` python mul_thread_reverse.py`
2. 循环运行
`python manage_time.py`  
定期运行，维护系统的IP地址
 