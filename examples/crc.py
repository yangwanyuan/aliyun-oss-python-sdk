# -*- coding: utf-8 -*-

import os, sys
import random
import string
import profile
import oss2


access_key_id = os.getenv('OSS_TEST_ACCESS_KEY_ID', '<你的AccessKeyId>')
access_key_secret = os.getenv('OSS_TEST_ACCESS_KEY_SECRET', '<你的AccessKeySecret>')
bucket_name = os.getenv('OSS_TEST_BUCKET', '<你的Bucket>')
endpoint = os.getenv('OSS_TEST_ENDPOINT', '<你的访问域名>')
region = os.getenv('OSS_TEST_REGION')
cmk = os.getenv("OSS_TEST_CMK")

# 确认上面的参数都填写正确了
for param in (access_key_id, access_key_secret, bucket_name, endpoint):
    assert '<' not in param, '请设置参数：' + param

auth = oss2.Auth(access_key_id, access_key_secret)
bucket = oss2.Bucket(auth, endpoint, bucket_name)

rsa_bucket = oss2.CryptoBucket(auth, endpoint, bucket_name, crypto_provider=oss2.LocalRsaProvider())

kms_bucket = oss2.CryptoBucket(auth, endpoint, bucket_name,
                         crypto_provider=oss2.AliKMSProvider(access_key_id, access_key_secret, region, cmk))



def random_string(n):
    return ''.join(random.choice(string.ascii_lowercase) for i in range(n))


def random_bytes(n):
    return oss2.to_bytes(random_string(n))

global cnt

def raw(cnt):
    for i in range(cnt):
        bucket.put_object(keys[i], datas[i])



def rsa(cnt):
    for i in range(cnt):
        rsa_bucket.put_object(keys[i], datas[i])


def kms(cnt):
    for i in range(cnt):
        # print(i)
        kms_bucket.put_object(keys[i], datas[i])


def raw1(cnt):
    for i in range(cnt):
        bucket.get_object(keys[i]).read()



def rsa1(cnt):
    for i in range(cnt):
        rsa_bucket.get_object(keys[i]).read()


def kms1(cnt):
    for i in range(cnt):
        # print(i)
        kms_bucket.get_object(keys[i]).read()

if __name__ == "__main__":

    if len(sys.argv) == 1:
        cnt = 1000
    else:
        cnt = int(sys.argv[1])

    keys = [random_string(1) for i in range(cnt)]
    datas = [random_bytes(1024) for i in range(cnt)]

    print('start profiling raw put')
    profile.run('raw(cnt)')
    print('start profiling raw get')
    profile.run('raw1(cnt)')
    # print('start profiling rsa put')
    # profile.run('rsa(cnt)')
    # print('start profiling rsa get')
    # profile.run('rsa1(cnt)')
    # print('start profiling kms put')
    # profile.run('kms(cnt)')
    # print('start profiling kms get')
    # profile.run('kms1(cnt)')







