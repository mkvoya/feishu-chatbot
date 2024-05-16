#!/bin/python3

import json
import time
from wxauto import *
import requests


wx = WeChat()  # 获取当前微信客户端
wx.GetSessionList()  # 获取会话列表
def get_default_messages():
    # 调用wxauto中的方法：GetAllMessage
    msgs = wx.GetAllMessage
    for msg in msgs:
        print('%s : %s' % (msg[0], msg[1]))

if __name__ == '__main__':
    config = json.load(open('.env.json'))
    URL = config['message_url']
    while True:
        r = requests.get(url=URL)
        data = r.json()
        if data.ok == "ok":
            wx.SendMsg(data.message, 'XXX群')
        time.sleep(5)   


