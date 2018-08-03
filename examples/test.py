# -*- coding: utf-8 -*-


import json
import os
import random
import string
from time import sleep

import time
import oss2

from aliyunsdkcore import client
from aliyunsdkcore.http import protocol_type, format_type, method_type
from aliyunsdkkms.request.v20160120 import ListKeysRequest, GenerateDataKeyRequest, DecryptRequest, EncryptRequest
# from aliyunsdkram.request.v20150501 import CreatePolicyRequest, AttachPolicyToUserRequest, CreateRoleRequest
from aliyunsdksts.request.v20150401 import AssumeRoleRequest

access_key_id = os.getenv('OSS_TEST_ACCESS_KEY_ID', '<你的AccessKeyId>')
access_key_secret = os.getenv('OSS_TEST_ACCESS_KEY_SECRET', '<你的AccessKeySecret>')
bucket_name = os.getenv('OSS_TEST_BUCKET', '<你的Bucket>')
endpoint = os.getenv('OSS_TEST_ENDPOINT', '<你的访问域名>')
region = os.getenv('OSS_TEST_REGION')
cmk = os.getenv("OSS_TEST_CMK")
sts_role_arn = os.getenv('OSS_TEST_STS_ARN', '<你的Role Arn>')


# 确认上面的参数都填写正确了
for param in (access_key_id, access_key_secret, bucket_name, endpoint):
    assert '<' not in param, '请设置参数：' + param

# clt = client.AcsClient('2NeLUvmJFYbrj2Eb', 'tpKbdpzCavhbYghxHih5urCw5lkBdx', 'cn-hangzhou')
# clt = client.AcsClient(access_key_id, access_key_secret, region)
# clt = client.AcsClient('LTAIMDXb6QuTm7tB', 'JEsZBpyscSrNGmXAHKLD6yf35RKGRV', 'cn-shanghai')
# clt = client.AcsClient('LTAIYEpMzqYUgy6o', '2p3b4jLLrPEB0kUTHmS0ZWvYGcTew6', 'cn-hangzhou')


key_id = '45ef024f-9e87-48ef-9863-ba19d8bd788e'

# cmk = '87b56458-7cef-4bfa-8a2b-d105755e4318'
cmk = 'a3e88ed4-6e5c-4ad9-be76-6c23053e6194'

info = ''

key = ''

# def create_role():
#     req = CreateRoleRequest.CreateRoleRequest()
#
#     req.set_accept_format(format_type.JSON)
#     req.set_method(method_type.POST)
#     req.set_RoleName("")


def list_key():
    global key_id
    req = ListKeysRequest.ListKeysRequest()

    req.set_accept_format(format_type.JSON)
    req.set_method(method_type.POST)
    req.set_PageNumber(1)
    req.set_PageSize(20)

    body = clt.do_action_with_exception(req)

    print(body.decode())

    j = json.loads(body)

    key_id = j['Keys']['Key'][0]['KeyId']


def generate_key(sts = None):
    req = GenerateDataKeyRequest.GenerateDataKeyRequest()

    req.set_accept_format(format_type.JSON)
    req.set_method(method_type.POST)

    req.set_KeyId(cmk)
    req.set_KeySpec('AES_256')
    req.set_NumberOfBytes(32)
    if sts:
        req.set_STSToken(sts)

    body = clt.do_action_with_exception(req)

    print(body.decode())
    global info, key

    j = json.loads(body)

    info = j['CiphertextBlob']
    key = j['Plaintext']


def decrypt_key(info):
    req = DecryptRequest.DecryptRequest()

    req.set_accept_format(format_type.JSON)
    req.set_method(method_type.POST)
    req.set_CiphertextBlob(info)
    body = clt.do_action_with_exception(req)

    print(body.decode())


def encrypt_key(info):
    req = EncryptRequest.EncryptRequest()

    req.set_accept_format(format_type.JSON)
    req.set_method(method_type.POST)
    req.set_KeyId(cmk)
    req.set_Plaintext(info)
    body = clt.do_action_with_exception(req)

    print(body.decode())

def create_policy():
    req = CreatePolicyRequest.CreatePolicyRequest()

    req.set_accept_format(format_type.JSON)
    req.set_method(method_type.POST)
    req.set_PolicyName('kms')
    req.set_PolicyDocument('{"Version": "1", "Statement": [{"Effect": "Allow","Action": ["kms:CreateKey",\
        "kms:GenerateDataKey", "kms:ListKeys", "kms:Encrypt", "kms:Decrypt" ], "Resource": \
        ["acs:kms:cn-shanghai:1574490449972580:key/*", "acs:kms:cn-shanghai:1574490449972580:key"]}]}')

    body = clt.do_action_with_exception(req)

    print(body.decode())

def attach_policy_to_user():
    req = AttachPolicyToUserRequest.AttachPolicyToUserRequest()

    req.set_accept_format(format_type.JSON)
    req.set_method(method_type.POST)
    req.set_PolicyType('Custom')
    req.set_PolicyName('kms')
    req.set_UserName('baiyubin')

    body = clt.do_action_with_exception(req)

    print(body.decode())

class StsToken(object):
    """AssumeRole返回的临时用户密钥
    :param str access_key_id: 临时用户的access key id
    :param str access_key_secret: 临时用户的access key secret
    :param int expiration: 过期时间，UNIX时间，自1970年1月1日UTC零点的秒数
    :param str security_token: 临时用户Token
    :param str request_id: 请求ID
    """
    def __init__(self):
        self.access_key_id = ''
        self.access_key_secret = ''
        self.expiration = 0
        self.security_token = ''
        self.request_id = ''


def fetch_sts_token(access_key_id, access_key_secret, role_arn):
    """子用户角色扮演获取临时用户的密钥
    :param access_key_id: 子用户的 access key id
    :param access_key_secret: 子用户的 access key secret
    :param role_arn: STS角色的Arn
    :return StsToken: 临时用户密钥
    """
    clt = client.AcsClient(access_key_id, access_key_secret, 'cn-shanghai')
    req = AssumeRoleRequest.AssumeRoleRequest()

    req.set_accept_format('json')
    req.set_RoleArn(role_arn)
    req.set_RoleSessionName('oss-python-sdk-example')

    body = clt.do_action_with_exception(req)

    print(body)
    j = json.loads(body)

    token = StsToken()

    token.access_key_id = j['Credentials']['AccessKeyId']
    token.access_key_secret = j['Credentials']['AccessKeySecret']
    token.security_token = j['Credentials']['SecurityToken']
    token.request_id = j['RequestId']
    token.expiration = oss2.utils.to_unixtime(j['Credentials']['Expiration'], '%Y-%m-%dT%H:%M:%SZ')

    return token


# 创建Bucket对象，所有Object相关的接口都可以通过Bucket对象来进行
# token = fetch_sts_token(access_key_id, access_key_secret, sts_role_arn)
# auth = oss2.StsAuth(token.access_key_id, token.access_key_secret, token.security_token)
# bucket = oss2.Bucket(auth, endpoint, bucket_name)
#
# bucket1 = oss2.Bucket(oss2.AuthV2(access_key_id, access_key_secret), endpoint, bucket_name)
#
# log_bucket = oss2.Bucket(oss2.AuthV2(access_key_id, access_key_secret), endpoint, 'ccc-test-002')


# def logging_test(bucket, name):
#     logging = oss2.models.BucketLogging(name, 'logging')
#     bucket.put_bucket_logging(logging)
#
#     bucket.put_object('1111', '123445')
#     bucket.put_object('1234', '123445')
#     bucket.put_object('sdga', '123445')
#
#     bucket.get_object('1111')
#     try:
#         bucket.get_object('sdfos')
#     except Exception as e:
#         print(e.message)
#
#     print(bucket.get_bucket_logging().target_bucket)
#
#     print(len(log_bucket.list_objects().object_list))

    # bucket.delete_bucket_logging()

# logging_test(bucket1, 'ccc-201501-02')
#
# logging_test(bucket, 'ccc-test-002')

# log_bucket.get_object_to_file('loggingccc-test-0012018-01-26-13-00-00-0001', '1.txt')
# oss2.Bucket(auth, endpoint, 'ccc-test-002').get_object_to_file('loggingccc-test-0012018-01-26-14-00-00-0001', '2.txt')


# oss2.Bucket(oss2.AuthV2(access_key_id, access_key_secret), endpoint, 'ymy-py-hz1-test').create_bucket()

# oss2.Bucket(oss2.AuthV2(access_key_id, access_key_secret), endpoint, 'python-sdk-travis-test').create_bucket()
# list_key()


# token = fetch_sts_token('LTAIMDXb6QuTm7tB', 'JEsZBpyscSrNGmXAHKLD6yf35RKGRV', 'acs:ram::1574490449972580:role/aaaaaa')
# token = fetch_sts_token('LTAIqZ0evqHQMMe5', '5xM8HuWkiPZeFWWu54kD2mcsDrzEhw', 'acs:ram::1574490449972580:role/aaaaaaa')

# clt = client.AcsClient(token.access_key_id, token.access_key_secret, 'cn-shanghai')
#
# generate_key(token.security_token)

# token1 = fetch_sts_token('LTAIMDXb6QuTm7tB', 'JEsZBpyscSrNGmXAHKLD6yf35RKGRV', 'acs:ram::1574490449972580:role/aaaaaaa')

# import logging
# logging.basicConfig(level=logging.DEBUG)

endpoint = 'http://10.101.221.135:8086'

# auth = oss2.Auth('LTAIW1PnC9D4KnKx', 'j5pPR4TqaE28PQGht1Yeij2yw8hc5A')
auth = oss2.Auth('LTAIXK2ASHmrG5uj', '6LuAAAY3mVMz5NQ4WkzYEMyRHjIQnX')
bucket_name = ''.join(random.choice(string.ascii_lowercase) for i in range(63)).lower()
bucket = oss2.Bucket(auth, endpoint, bucket_name)

# for i in service.list_buckets().buckets:
#     if i.name == 'py-oss-sdk-us-w-test' or i.name == 'ymy-py-hz2-test':
#         continue
#     try:
#         b = oss2.Bucket(auth, endpoint, i.name)
#         for j in b.list_objects().object_list:
#             b.delete_object(j.key)
#         b.delete_bucket()
#     except:
#         pass

#aliyunossudfdefaultrole
# token1 = fetch_sts_token('LTAIUsJMkftdlPdY', '7HruD4NkKBIG56zmy9kdLh5MMKTbvJ', 'acs:ram::1029817384344108:role/sts-test')

# b = oss2.Bucket(oss2.StsAuth(token1.access_key_id, token1.access_key_secret, token1.security_token), endpoint, 'test1111112312432545')
# b = oss2.Bucket(oss2.AnonymousAuth(), endpoint, 'test1111112312432545')
#
# # b.create_bucket(permission=oss2.BUCKET_ACL_PUBLIC_READ_WRITE)
# #
# # b.put_bucket_acl(permission=oss2.BUCKET_ACL_PUBLIC_READ)
#
# # info = b.get_bucket_info()
# # print("{0} {1} {2}".format(info.name, info.owner.id, info.acl.grant))
# b.put_object('1', '1')
# r = b.get_object_meta('1')

# b = oss2.Bucket(auth, endpoint, 'ymy-py-hz1-test', connect_timeout=100000)

class AdminAuth(oss2.auth.AuthBase):
    """签名版本1"""
    _subresource_key_set = frozenset(
        ['response-content-type', 'response-content-language',
         'response-cache-control', 'logging', 'response-content-encoding',
         'acl', 'uploadId', 'uploads', 'partNumber', 'group', 'link',
         'delete', 'website', 'location', 'objectInfo', 'objectMeta',
         'response-expires', 'response-content-disposition', 'cors', 'lifecycle',
         'restore', 'qos', 'referer', 'stat', 'bucketInfo', 'append', 'position', 'security-token',
         'live', 'comp', 'status', 'vod', 'startTime', 'endTime', 'x-oss-process',
         'symlink', 'callback', 'callback-var']
    )

    def _sign_request(self, req, bucket_name, key):
        req.headers['date'] = oss2.utils.http_date()
        req.headers['x-oss-dc-operation'] = '123'
        signature = self.__make_signature(req, bucket_name, key)
        req.headers['authorization'] = "OSS-ADMIN {0}:{1}".format(self.id, signature)

    def _sign_url(self, req, bucket_name, key, expires):
        expiration_time = int(time.time()) + expires

        req.headers['date'] = str(expiration_time)
        signature = self.__make_signature(req, bucket_name, key)

        req.params['OSSAccessKeyId'] = self.id
        req.params['Expires'] = str(expiration_time)
        req.params['Signature'] = signature

        return req.url + '?' + '&'.join(oss2.auth._param_to_quoted_query(k, v) for k, v in req.params.items())

    def __make_signature(self, req, bucket_name, key):
        string_to_sign = self.__get_string_to_sign(req, bucket_name, key)


        h = oss2.auth.hmac.new((self.secret+'ebaf2c0c100846b990b59b4173152ed0'), (string_to_sign), oss2.auth.hashlib.sha1)
        return oss2.utils.b64encode_as_string(h.digest())

    def __get_string_to_sign(self, req, bucket_name, key):
        resource_string = self.__get_resource_string(req, bucket_name, key)
        headers_string = self.__get_headers_string(req)

        content_md5 = req.headers.get('content-md5', '')
        content_type = req.headers.get('content-type', '')
        date = req.headers.get('date', '')
        return '\n'.join([req.method,
                          content_md5,
                          content_type,
                          date,
                          headers_string + resource_string])

    def __get_headers_string(self, req):
        headers = req.headers
        canon_headers = []
        for k, v in headers.items():
            lower_key = k.lower()
            if lower_key.startswith('x-oss-'):
                canon_headers.append((lower_key, v))

        canon_headers.sort(key=lambda x: x[0])

        if canon_headers:
            return '\n'.join(k + ':' + v for k, v in canon_headers) + '\n'
        else:
            return ''

    def __get_resource_string(self, req, bucket_name, key):
        if not bucket_name:
            return '/'
        else:
            return '/{0}/{1}{2}'.format(bucket_name, key, self.__get_subresource_string(req.params))

    def __get_subresource_string(self, params):
        if not params:
            return ''

        subresource_params = []
        for key, value in params.items():
            if key in self._subresource_key_set:
                subresource_params.append((key, value))

        subresource_params.sort(key=lambda e: e[0])

        if subresource_params:
            return '?' + '&'.join(self.__param_to_query(k, v) for k, v in subresource_params)
        else:
            return ''

    def __param_to_query(self, k, v):
        if v:
            return k + '=' + v
        else:
            return k



# admin_auth = AdminAuth('r0xo6std563llv4', 'YWJ3NGI2ZnAzc3p6N29vb3IycXM=')

b = oss2.Bucket(auth, endpoint, 'test-test-123213', connect_timeout=100000)


# b.create_bucket()

# print(b.get_bucket_location().location)

#
# b.create_bucket()
res = b.put_object('123', '12345')
print(res.headers)
print(res.status)
# # print(b.get_object('123').read())
# b.delete_object('123')
# res = b.get_object('123')
# print(res.headers)
# print(res.read())


# bb = oss2.Bucket(auth, endpoint, 'ymy-test-private1')
# bb.create_bucket(oss2.BUCKET_ACL_PRIVATE)
# bb.put_object('123', '123')

