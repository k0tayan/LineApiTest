# -*- coding: utf-8 -*-
import json
import requests
import ssl
import rsa

from thrift.protocol import TCompactProtocol
from thrift.transport import THttpClient
import TalkService
import LineLoginService
from ttypes import LoginRequest
from ttypesDefault import *


ssl._create_default_https_context = ssl._create_unverified_context

host = 'https://gd2.line.naver.jp'
LINE_AUTH_QUERY_PATH = '/api/v4p/rs'
LINE_AUTH_QUERY_PATH_FIR        = '/api/v4/TalkService.do'
LINE_CERTIFICATE_PATH = '/Q'
LINE_API_QUERY_PATH_FIR = '/S4'
UA, LA = ("Line/7.14.0 iPad5,1 10.2.0", 'IOSIPAD\t7.14.0\tiPhone OS\t10.12.0')
_session    = requests.session()



email = "aaaa@test.com"
password = "aaaaaaa"


# 関数定義開始
def getJson(url, headers=None):
    if headers is None:
        return json.loads(_session.get(url).text)
    else:
        return json.loads(_session.get(url, headers=headers).text)

def defaultCallback(str):
    print(str)

def createTransport(path=None, update_headers=None, service=None):
    Headers = {
        'User-Agent': UA,
        'X-Line-Application': LA,
        "x-lal": "ja-US_US",
    }
    Headers.update({"x-lpqs" : path})
    if(update_headers is not None):
        Headers.update(update_headers)
    transport = THttpClient.THttpClient(host + path)
    transport.setCustomHeaders(Headers)
    protocol = TCompactProtocol.TCompactProtocol(transport)
    client = service(protocol)
    return client

# 関数定義ここまで


class LineCallback(object):

    def __init__(self, callback):
        self.callback = callback

    def PinVerified(self, pin):
        self.callback("Input this PIN code '" + pin + "' on your LINE for smartphone in 2 minutes")
    def default(self, str):
        self.callback(str)

client = createTransport(LINE_AUTH_QUERY_PATH_FIR, None, TalkService.Client)
rsa_number = client.getRSAKeyInfo(IdentityProvider.LINE)
session_key = rsa_number.sessionKey
message = (chr(len(session_key)) + session_key +
           chr(len(email)) + email +
           chr(len(password)) + password).encode('utf-8')

keyname, n, e = rsa_number.keynm, rsa_number.nvalue, rsa_number.evalue
pub_key = rsa.PublicKey(int(n, 16), int(e, 16))
crypto = rsa.encrypt(message, pub_key).hex()

client = createTransport(LINE_AUTH_QUERY_PATH, None, LineLoginService.Client)
req = LoginRequest()
req.type = 0
req.identityProvider = 1
req.identifier = keyname
req.password = crypto
req.keepLoggedIn = 1
req.accessLocation = '192.168.0.1'
req.systemName = "test2"
req.e2eeVersion = 1
res = client.loginZ(req)
clb = LineCallback(defaultCallback)
clb.PinVerified(res.pinCode)
header = {
        'User-Agent': UA,
        'X-Line-Application': LA,
        "x-lal" : "ja-US_US",
        "x-lpqs" : LINE_AUTH_QUERY_PATH_FIR,
        'X-Line-Access': res.verifier
}
getAccessKey = getJson(host + LINE_CERTIFICATE_PATH, header)
req = LoginRequest()
req.type = 1
req.verifier = res.verifier
req.e2eeVersion = 1
res = client.loginZ(req)
client = createTransport(LINE_API_QUERY_PATH_FIR, {'X-Line-Access':res.authToken}, TalkService.Client)
print(res.authToken)
print(client.getProfile())

