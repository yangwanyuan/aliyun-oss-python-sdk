# -*- coding: utf-8 -*-

import os
import shutil

import oss2


# 以下代码展示了如何启用Http2.0来发送请求。


# 首先初始化AccessKeyId、AccessKeySecret、Endpoint等信息。
# 通过环境变量获取，或者把诸如“<你的AccessKeyId>”替换成真实的AccessKeyId等。
#
# 以杭州区域为例，Endpoint可以是：
#   https://oss-cn-hangzhou.aliyuncs.com
# 目前Http2.0只支持HTTPS协议访问。
access_key_id = os.getenv('OSS_TEST_ACCESS_KEY_ID', '<你的AccessKeyId>')
access_key_secret = os.getenv('OSS_TEST_ACCESS_KEY_SECRET', '<你的AccessKeySecret>')
bucket_name = os.getenv('OSS_TEST_BUCKET', '<你的Bucket>')
endpoint = os.getenv('OSS_TEST_ENDPOINT', '<你的访问域名>')


# 确认上面的参数都填写正确了
for param in (access_key_id, access_key_secret, bucket_name, endpoint):
    assert '<' not in param, '请设置参数：' + param

# 创建Bucket对象，所有Object相关的接口都可以通过Bucket对象来进行
#bucket = oss2.Bucket(oss2.Auth(access_key_id, access_key_secret), endpoint, bucket_name, enable_http20=True)
#bucket = oss2.Bucket(oss2.Auth(access_key_id, access_key_secret), endpoint, bucket_name)
bucket = oss2.Bucket(oss2.make_auth(access_key_id, access_key_secret, 'v1'), endpoint, bucket_name, enable_http20=True)

# 上传一段字符串。Object名是motto.txt，内容是一段名言。
#bucket.put_object('motto.txt', 'Never give up. - Jack Ma')
#bucket.put_object('motto.txt', '', headers={"Content-Length":"0"})
#bucket.put_object('motto.txt', '')

## 测试append
#print __name__, "0" * 10
#bucket.delete_object('motto.txt-a')
#print __name__, "1" * 10
#bucket.append_object('motto.txt-a', 0, 'aaaa')
#print __name__, "2" * 10
#bucket.append_object('motto.txt-a', 0, 'bbbb')
##bucket.append_object('motto.txt-a', 4, 'bbbb')
#print __name__, "3" * 10
##try:
##    bucket.append_object('motto.txt-a', 4, 'bbbb')
##    print __name__, "4" * 10
##except:
##    print __name__, "!!!!!!"
#bucket.delete_object('motto.txt-a')
#print __name__, "5" * 10

### 测试empty
##bucket.put_object('motto.txt', '')
##bucket.put_object('motto.txt', '', headers={"Content-Length":"0"})
#
#with open('tempfile', 'wb') as f:
#    f.write(b'')
##bucket.put_object_from_file('motto.txt', 'tempfile')
#bucket.put_object_from_file('motto.txt', 'tempfile', headers={"Content-Length":"0"})
#os.remove(u'tempfile')

# 测试 stream
bucket.put_object('stream-1', 'a'*1024*1024)
# 获取OSS上的文件，一边读取一边写入到另外一个OSS文件
src = bucket.get_object('stream-1')
#result = bucket.put_object('stream-2', src)
result = bucket.put_object('stream-2', src, headers={'Content-Length':'1048576'})

### 测试 generator
#def make_generator(content, chunk_size):
#    def generator():
#        offset = 0
#        while offset < len(content):
#            n = min(chunk_size, len(content) - offset)
#            yield content[offset:offset+n]
#
#            offset += n
#
#    return generator()
#
#content = 'a' * (1024 * 1024 + 1)
#
#bucket.put_object('generator-1', make_generator(content, 8192))

## 测试 modified since
#import time
#bucket.put_object('modified_since', 'a'*16)
#bucket.get_object('modified_since',headers={'if-modified-since': oss2.utils.http_date(int(time.time()) + 60)}, byte_range=(0, 7))

### 测试 get_object_meta
#bucket.put_object('motto.txt', 'Never give up. - Jack Ma')
#result = bucket.get_object_meta('motto.txt')

## 测试非法的文件名
#try:
#    bucket.put_object('/invalid-object-name', 'aaaaaaaaaaaaaaaa')
#except:
#    print "Invalid Object Name"

## 测试 exist_object
#print bucket.object_exists("ccc")

# 下载到本地文件
bucket.get_object_to_file('motto.txt', '本地文件名.txt')

# 清除本地文件
os.remove(u'本地文件名.txt')
