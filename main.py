import hashlib
import hmac
import json
import logging
import socket
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import List

import requests
import yaml


def setup_logging():
    """
    设置日志记录。
    """
    _logger = logging.getLogger()
    _logger.setLevel(logging.INFO)

    file_handler = RotatingFileHandler("log", maxBytes=200 * 1024, backupCount=1)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    _logger.addHandler(file_handler)
    _logger.addHandler(console_handler)

    return _logger


logger = setup_logging()


def read_config(node):
    with open('config.yaml', 'r', encoding='utf-8') as file:
        try:
            config = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            logging.error(f"Error reading YAML file: {exc}")
    return config.get(node, {})


class EdgeOneClient:
    def __init__(self):
        self.service: str = 'teo'
        self.host: str = 'teo.tencentcloudapi.com'
        self.version: str = '2022-09-01'
        self.algorithm: str = 'TC3-HMAC-SHA256'
        self.content_type: str = 'application/json; charset=utf-8'
        self.http_request_method: str = 'POST'
        self.canonical_uri: str = '/'
        self.canonical_query_string: str = ''
        self.signed_headers: str = 'content-type;host;x-tc-action'

        secret = read_config('TencentCloud')
        self.secret_id = secret.get("SecretId")
        self.secret_key = secret.get("SecretKey")

    def signature(self, action, body) -> dict:
        timestamp: int = int(time.time())
        date: str = datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d')

        payload = json.dumps(body)

        hashed_request_payload: str = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        canonical_headers: str = f'content-type:{self.content_type}\nhost:{self.host}\nx-tc-action:{action.lower()}\n'
        canonical_request: str = (self.http_request_method + '\n' +
                                  self.canonical_uri + '\n' +
                                  self.canonical_query_string + '\n' +
                                  canonical_headers + '\n' +
                                  self.signed_headers + '\n' +
                                  hashed_request_payload)

        # 拼接待签名字符串
        credential_scope = f'{date}/{self.service}/tc3_request'
        hashed_canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        string_to_sign = f"{self.algorithm}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}"

        # 计算签名
        def sign(key, message):
            return hmac.new(key, message.encode('utf-8'), hashlib.sha256).digest()

        secret_date = sign(('TC3' + self.secret_key).encode('utf-8'), date)
        secret_service = sign(secret_date, self.service)
        secret_signing = sign(secret_service, 'tc3_request')
        signature = hmac.new(secret_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        authorization = (f'{self.algorithm} '
                         f'Credential={self.secret_id}/{credential_scope}, '
                         f'SignedHeaders={self.signed_headers}, '
                         f'Signature={signature}')
        # 发送请求
        headers = {
            'Authorization': authorization,
            'Content-Type': self.content_type,
            'Host': self.host,
            'X-TC-Action': action,
            'X-TC-Version': self.version,
            'X-TC-Timestamp': str(timestamp)
        }
        return headers

    def modify_origin_group(self, zone_id, origin_group_id, iplist):
        body = {
            "ZoneId": zone_id,
            "GroupId": origin_group_id,
            "Records": [{"Record": ip, "Type": "IP_DOMAIN", "Weight": 100} for ip in iplist]
        }
        response = requests.post(
            f'https://{self.host}',
            headers=self.signature('ModifyOriginGroup', body),
            json=body
        ).json()
        error = response.get("Response", {}).get("Error", {})
        return error.get("Message", ""), error.get("Code", "")

    def describe_origin_group(self, zone_id, origin_group_id):
        body = {"ZoneId": zone_id, "Filters": [{"Name": "origin-group-id", "Values": [origin_group_id]}]}
        response = requests.post(
            f'https://{self.host}',
            headers=self.signature('DescribeOriginGroup', body),
            json=body
        ).json()
        origin_groups = response.get('Response', {}).get('OriginGroups', {})

        if len(origin_groups) >= 1:
            origin_records = origin_groups[0].get('OriginRecords')
            iplist = [i.get('Record') for i in origin_records]
            return set(iplist)
        else:
            logger.error(f"OriginGroup does not exist. <{zone_id}:{origin_group_id}>")
            return None


class DNSPodClient:
    def __init__(self):
        self.service: str = 'dnspod'
        self.host: str = 'dnspod.tencentcloudapi.com'
        self.version: str = '2021-03-23'
        self.algorithm: str = 'TC3-HMAC-SHA256'
        self.content_type: str = 'application/json; charset=utf-8'
        self.http_request_method: str = 'POST'
        self.canonical_uri: str = '/'
        self.canonical_query_string: str = ''
        self.signed_headers: str = 'content-type;host;x-tc-action'

        secret = read_config('TencentCloud')
        self.secret_id = secret.get("SecretId")
        self.secret_key = secret.get("SecretKey")

    def signature(self, action, body) -> dict:
        timestamp: int = int(time.time())
        date: str = datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d')

        payload = json.dumps(body)

        hashed_request_payload: str = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        canonical_headers: str = f'content-type:{self.content_type}\nhost:{self.host}\nx-tc-action:{action.lower()}\n'
        canonical_request: str = (self.http_request_method + '\n' +
                                  self.canonical_uri + '\n' +
                                  self.canonical_query_string + '\n' +
                                  canonical_headers + '\n' +
                                  self.signed_headers + '\n' +
                                  hashed_request_payload)

        # 拼接待签名字符串
        credential_scope = f'{date}/{self.service}/tc3_request'
        hashed_canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        string_to_sign = f"{self.algorithm}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}"

        # 计算签名
        def sign(key, message):
            return hmac.new(key, message.encode('utf-8'), hashlib.sha256).digest()

        secret_date = sign(('TC3' + self.secret_key).encode('utf-8'), date)
        secret_service = sign(secret_date, self.service)
        secret_signing = sign(secret_service, 'tc3_request')
        signature = hmac.new(secret_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        authorization = (f'{self.algorithm} '
                         f'Credential={self.secret_id}/{credential_scope}, '
                         f'SignedHeaders={self.signed_headers}, '
                         f'Signature={signature}')
        # 发送请求
        headers = {
            'Authorization': authorization,
            'Content-Type': self.content_type,
            'Host': self.host,
            'X-TC-Action': action,
            'X-TC-Version': self.version,
            'X-TC-Timestamp': str(timestamp)
        }
        return headers

    @staticmethod
    def decode_full_domain(full_domain):
        full_domain_list = full_domain.split('.')

        if len(full_domain_list) == 2:
            domain =  full_domain
            subdomain = "@"
        else:
            domain =  '.'.join(full_domain_list[1:])
            subdomain = full_domain_list[0]

        return domain, subdomain

    def modify_dns_record(self, full_domain, iplist, record_id):
        domain, subdomain = self.decode_full_domain(full_domain)

        body = {
                "Domain": domain,
                "SubDomain": subdomain,
                "RecordType": "AAAA",
                "RecordId": record_id,
                "RecordLine": "默认",
                "Value": list(iplist)[0],
                "TTL": 600
            }
        requests.post(
            f'https://{self.host}',
            headers=self.signature("ModifyRecord", body),
            json=body
        )

    def create_dns_record(self, full_domain, iplist):
        domain, subdomain = self.decode_full_domain(full_domain)

        body = {
                "Domain": domain,
                "RecordType": "AAAA",
                "RecordLine": "默认",
                "Value": list(iplist)[0],
                "SubDomain": subdomain,
                "TTL": 600
            }
        response = requests.post(
            f'https://{self.host}', headers=self.signature("CreateRecord", body), json=body
        ).json()
        error = response.get("Response", {}).get("Error", {})
        return error.get("Message", ""), error.get("Code", "")

    def delete_dns_record(self, full_domain, record_id):
        domain, subdomain = self.decode_full_domain(full_domain)

        body = {"Domain": domain, "RecordId": record_id}
        requests.post(f'https://{self.host}', headers=self.signature("DeleteRecord", body), json=body)

    def describe_dns_record(self, full_domain):
        domain, subdomain = self.decode_full_domain(full_domain)

        body = {
                "Domain": domain,
                "Subdomain": subdomain,
                "RecordType": "AAAA",
            }
        responses = requests.post(
            f'https://{self.host}',
            headers=self.signature("DescribeRecordList", body),
            json=body
        ).json().get('Response').get('RecordList')
        return responses


class IPv6Tool:
    def __init__(self):
        self.ipv6:list[str]|None = self.get_ipv6_list()
        self.public_ipv6:set[str]|None = self.filter_public_ipv6()

    @staticmethod
    def ipv6_ping_test(ipv6):
        res = requests.get(
            url=F'https://ipw.cn/api/ping/ipv6/{ipv6}/4/all',
            headers={
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                              '(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0',
                'referer': 'https://ipw.cn/ipv6ping/'
            })

        if 'PingFailed' in res.text:
            logger.info(f"Address <{ipv6}> Ping Failed...")
            return False
        else:
            logger.info(f"Address <{ipv6}> Ping Success...")
            return True

    @staticmethod
    def get_ipv6_list():
        addr_infos = socket.getaddrinfo(socket.gethostname(), None)
        ipv6_list = [
            addr_info[4][0]
            for addr_info in addr_infos
            if addr_info[0] == socket.AF_INET6 and addr_info[4][3] == 0
        ]
        return ipv6_list

    def filter_public_ipv6(self):
        if self.ipv6:
            public_ipv6_list = [ipv6 for ipv6 in self.ipv6 if self.ipv6_ping_test(ipv6)]
            logger.info(f"Public IPv6 addresses: {public_ipv6_list}")
            return set(public_ipv6_list)
        else:
            logger.info(f"No IPv6 addresses.")
            return None


class Dingtalk:
    def __init__(self):
        self.webhook = read_config('DingTalk').get('webhook')

    def notice_no_public_ipv6(self):
        requests.post(
            self.webhook,
            json={
                "markdown": {
                    "title": "Dynamic EdgeOne/DNS",
                    "text": "> 信息：无法获取公网IPv6，跳过此次更新。"
                },
                "msgtype": "markdown"
            })

    def notice_eo_result(self, site_tag:str, zone:str, public_ipv6:List[str], message:str):
        ipv6_text = [f"- {item}\n" for item in public_ipv6]

        requests.post(
            self.webhook,
            json={
                "markdown": {
                    "title": "EdgeOne源站更新",
                    "text": f"### EdgeOne源站更新\n\n"
                            f"**标签：** {site_tag}\n\n"
                            f"**站点：** {zone}\n\n"
                            f"**信息：** {message}\n\n"
                            f"**IPV6：** \n\n{",".join(ipv6_text)}"
                }, "msgtype": "markdown"}
        )

    def notice_dns_result(self, domain:str, public_ipv6:List[str], message:str):

        requests.post(
            self.webhook,
            json={
                "markdown": {
                    "title": "DNS解析更新",
                    "text": f"### DNS解析更新\n\n"
                            f"**域名：** {domain}\n\n"
                            f"**信息：** {message}\n\n"
                            f"**IPV6：** {public_ipv6[0]}"
                }, "msgtype": "markdown"}
        )


def eo_main(public_ipv6:set, groups):
    eo_client = EdgeOneClient()
    dingtalk = Dingtalk()

    def oring_group_need_update(_zone, _og, _tag):
        if public_ipv6 == eo_client.describe_origin_group(_zone, _og):
            logger.info(f"IP address unchanged, OriginGroup {_tag} no update needed.")
            return False
        else:
            logger.info(f"IP address changed, New IP <{public_ipv6}>")
            return True

    if public_ipv6:
        for item in groups:
            zone, og, tag = item.get('ZoneId'), item.get('OriginGroupId'), item.get('Tag')
            if oring_group_need_update(zone, og, tag):
                error_msg, error_code = eo_client.modify_origin_group(zone, og, public_ipv6)
                if not error_code and not error_msg:
                    error_msg = F"Successfully updated the OriginGroup."
                logger.info(f"{error_code}:{error_msg}")
                dingtalk.notice_eo_result(tag, zone, list(public_ipv6), error_msg)
    else:
        logger.info(f"Cannot Get IPv6 address, Skip update all OriginGroup.")
        dingtalk.notice_no_public_ipv6()


def dns_main(public_ipv6:set[str], full_domains):
    DNSPod = DNSPodClient()
    dingtalk = Dingtalk()

    def dns_record_check(_full_domain):
        _records = DNSPod.describe_dns_record(full_domain)

        if _records:
            skip_count = 0
            for _record in _records:
                if _record["Value"] in list(public_ipv6):
                    logger.info(f"IPv6 address is not change, Skip modify {_full_domain} DNS.")
                    skip_count += 1
                else:
                    logger.info(f"IPv6 address is exp, delete one {_full_domain} DNS record.")
                    DNSPod.delete_dns_record(full_domain, _record['RecordId'])
            if skip_count:
                return False
            else:
                return True
        else:
            return True


    if public_ipv6:
        for full_domain in full_domains:
            if dns_record_check(full_domain):
                error_msg, error_code = DNSPod.create_dns_record(full_domain, public_ipv6)
                if not error_code and not error_msg:
                    error_msg = F"Successfully updated DNS."
                logger.info(f"{error_code}:{error_msg}")
                dingtalk.notice_dns_result(full_domain, list(public_ipv6), error_msg)
    else:
        logger.info(f"Cannot Get IPv6 address, Skip update all DNS record.")
        dingtalk.notice_no_public_ipv6()



if __name__ == "__main__":
    ipv6_tool = IPv6Tool()

    eo_groups = read_config("EdgeOne")
    if eo_groups:
        eo_main(ipv6_tool.public_ipv6, eo_groups)

    domains = read_config('DDNS')
    if domains:
        dns_main(ipv6_tool.public_ipv6, domains)
