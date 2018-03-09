#!/usr/bin/python
#-*- coding:utf-8 -*-

# ddns.py
# Check current public ip and security group, if not match, update security group.
# Author: Julian Wang
# 2018/03/07

import os
import re
import json
import time

from QcloudApi.qcloudapi import QcloudApi

'''
module: 设置需要加载的模块
已有的模块列表：
cvm      对应   cvm.api.qcloud.com
cdb      对应   cdb.api.qcloud.com
lb       对应   lb.api.qcloud.com
trade    对应   trade.api.qcloud.com
sec      对应   csec.api.qcloud.com
image    对应   image.api.qcloud.com
monitor  对应   monitor.api.qcloud.com
cdn      对应   cdn.api.qcloud.com
'''
# Security Group module
module = 'dfw'

# Log function
def log(msg):
	'''
	Change the log directory if necessary
	'''
    log_file = r"/root/update_security_group.log"
    if os.path.exists(log_file):
        fp = open(log_file,'a')
    else:
        fp = open(log_file,'w')
    log_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    fp.write("%s - %s\n" % (log_time,msg))
    fp.close()

# Execute shell command
def execCmd(cmd):
    r = os.popen(cmd)
    text = r.read().strip('\n')
    r.close()
    return text

# Check external IP
def check_my_ip():
    url = "http://members.3322.org/dyndns/getip"
    cmd = "wget --quiet --no-check-certificate --output-document=- %s" % url
    ret = execCmd(cmd)

    if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ret) != None:
        return ret
    else:
        log("Can't get my external ip. exit")
        exit(-1)

# Check current security group policy
def check_security_group(config,sgID):
    action = 'DescribeSecurityGroupPolicys'
    action_params = {
    'sgId':sgID,
    }

    try:
        service = QcloudApi(module, config)
#        print(service.generateUrl(action, action_params))
        ret = service.call(action, action_params)
    except Exception as e:
        import traceback
        log(traceback.format_exc())
    
    dict = json.loads(ret)
    data = dict['data']['ingress']
    for i in data:
'''
Modify "YOUR_POLICY_DESCRIPTION" to your description of specified policy
目前只支持匹配单条规则，所以不要添加同样的描述到多条规则。
'''
        if i.has_key('desc') and "YOUR_POLICY_DESCRIPTION" in i['desc']:
            cidrIp = i['cidrIp']
            index = i['index']
            return cidrIp,index,i

def update_security_group(config, sgID, index, policys):
    action = 'ModifySingleSecurityGroupPolicy'
    action_params = {
    'sgId':sgID,
    'direction':'ingress',
    'index':index,
    'policys':policys,
    }
 
    try:
        service = QcloudApi(module, config)
        print(service.generateUrl(action, action_params))
        print(service.call(action, action_params))
    except Exception as e:
        import traceback
        log(traceback.format_exc())
    

def main():
    '''
    config: 云API的公共参数
	You need modify secretId, secretKey and sgID of your security group
    '''
    config = {
        'Region': 'sh',
        'secretId': '您的secretId',
        'secretKey': '您的secretKey',
        'method': 'GET',
        'SignatureMethod': 'HmacSHA1'
    }
    sgID = '您的security_group_id'

    log("================  Start  ================")
    my_ip = check_my_ip()
    
    record,index,policys = check_security_group(config,sgID)
    log("My external ip is %s, My security group record is %s" % (my_ip, record))

# 目前开通的是B段安全组，所以匹配的是class B，可以在这里修改为获取/24或者/32
    segment = my_ip.split('.')[0] + '.' + my_ip.split('.')[1] + '.0.0/16'

    if segment != record:
        log("Not match. Update security group record now")
        policys['cidrIp'] = segment
        update_security_group(config, sgID, index, policys)
    else:
        log("Match. Do nothing")
    log("================   End   ================")


main()
