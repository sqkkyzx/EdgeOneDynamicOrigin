import hashlib
import hmac
import json
import logging
import re
import socket
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import List

import requests
import yaml
import sys


def _setup_logging():
    """
    设置日志记录。
    """
    _logger = logging.getLogger()
    _logger.setLevel(logging.INFO)

    file_handler = RotatingFileHandler("log.txt", maxBytes=200 * 1024, backupCount=1, encoding="utf-8")
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    _logger.addHandler(file_handler)
    _logger.addHandler(console_handler)

    return _logger

def _read_config():
    if len(sys.argv) < 2:
        config_file = "config.yaml"
    else:
        config_file = sys.argv[1]

    with open(config_file, 'r', encoding='utf-8') as file:
        try:
            _config = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            logging.error(f"无法读取配置文件 {config_file} : {exc}")
    return _config

def _get_hostname():
    pattern = r'[^a-zA-Z0-9_-]'
    _hostname = socket.gethostname().lower()
    if re.search(pattern, _hostname) is not None:
        raise ValueError("主机名包含不允许的字符")
    else:
        return _hostname


config = _read_config()
hostname = _get_hostname()
logger = _setup_logging()


class QcloudClient:
    def __init__(self, secret, service='teo', version='2022-09-01'):
        self.service: str = service
        self.host: str = f'{service}.tencentcloudapi.com'
        self.version: str = version
        self.algorithm: str = 'TC3-HMAC-SHA256'
        self.content_type: str = 'application/json; charset=utf-8'
        self.http_request_method: str = 'POST'
        self.canonical_uri: str = '/'
        self.canonical_query_string: str = ''
        self.signed_headers: str = 'content-type;host;x-tc-action'

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
        body = {"ZoneId": zone_id, "GroupId": origin_group_id,
                "Records": [{"Record": ip, "Type": "IP_DOMAIN", "Weight": 100} for ip in iplist]}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('ModifyOriginGroup', body), json=body
        ).json()
        error = response.get("Response", {}).get("Error", {})
        return error.get("Message", ""), error.get("Code", "")

    def describe_origin_group(self, zone_id):
        body = {"ZoneId": zone_id, "Filters": [{"Name": "origin-group-name", "Values": [hostname]}]}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('DescribeOriginGroup', body), json=body
        ).json()
        return response.get('Response', {}).get('OriginGroups', {})

    def create_origin_group(self, zone_id, iplist):
        body = {"ZoneId": zone_id, "Name": hostname, "Type": "HTTP",
                "Records": [{"Record": ip, "Type": "IP_DOMAIN"} for ip in iplist]}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('CreateOriginGroup', body), json=body
        ).json()
        error = response.get("Response", {}).get("Error", {})
        return error.get("Message", ""), error.get("Code", "")

    def modify_dns_record(self, top_domain, sub_domain, record_type, iplist, record_id):

        body = {
                "Domain": top_domain,
                "SubDomain": sub_domain,
                "RecordType": record_type,
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

    def create_dns_record(self, top_domain, sub_domain, record_type, iplist):

        body = {
                "Domain": top_domain,
                "RecordType": record_type,
                "RecordLine": "默认",
                "Value": list(iplist)[0],
                "SubDomain": sub_domain,
                "TTL": 600
            }
        response = requests.post(
            f'https://{self.host}', headers=self.signature("CreateRecord", body), json=body
        ).json()
        error = response.get("Response", {}).get("Error", {})
        return error.get("Message", ""), error.get("Code", "")

    def delete_dns_record(self, top_domain, record_id):

        body = {"Domain": top_domain, "RecordId": record_id}
        requests.post(f'https://{self.host}', headers=self.signature("DeleteRecord", body), json=body)

    def describe_dns_record(self, top_domain, sub_domain, record_type):

        body = {
                "Domain": top_domain,
                "Subdomain": sub_domain,
                "RecordType": record_type,
            }
        responses = requests.post(
            f'https://{self.host}',
            headers=self.signature("DescribeRecordList", body),
            json=body
        ).json().get('Response').get('RecordList', [])
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
            logger.info(f"地址 <{ipv6}> Ping 测试失败。")
            return False
        else:
            logger.info(f"地址 <{ipv6}> Ping 测试通过，是公网地址。")
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
            logger.info(f"本机公网 IPV6 地址为: {public_ipv6_list}")
        else:
            logger.info(f"无法验证公网 IPV6 地址，将根据 ISP 前缀筛选。")
            public_ipv6_list = [ipv6 for ipv6 in self.ipv6 if ipv6.startswith("240e") or ipv6.startswith("2408") or ipv6.startswith("2409")]

        if public_ipv6_list:
            return set(public_ipv6_list)
        else:
            return None

class Dingtalk:
    def __init__(self, webhook):
        self.webhook = webhook

    def notice_no_public_ipv6(self):
        requests.post(
            self.webhook,
            json={
                "markdown": {
                    "title": "无法获取IP",
                    "text": f"> 信息：{hostname}无法获取公网IPv6，跳过此次更新。"
                },
                "msgtype": "markdown"
            })

    def notice_eo_result(self, site_tag:str, zone_id:str, public_ipv6:List[str], message:str):
        ipv6_text = [f"- {item}\n" for item in public_ipv6]

        requests.post(
            self.webhook,
            json={
                "markdown": {
                    "title": "EdgeOne源站更新",
                    "text": f"### EdgeOne源站更新\n\n"
                            f"**标签：** {site_tag}\n\n"
                            f"**站点：** {zone_id}\n\n"
                            f"**信息：** {message}\n\n"
                            f"**IPV6：** \n\n{"\n".join(ipv6_text)}"
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


def main():
    iptool = IPv6Tool()
    dingtalk = Dingtalk(config.get('DingTalkWebhook'))
    eo_zones = config.get("EdgeOneZoneId")
    domains = config.get('DnsPodRecord')
    qcloud_secret = config.get('TencentCloud')

    if not iptool.public_ipv6:
        logger.info(f"无法获取 IPV6 地址，跳过后续所有步骤。")
        dingtalk.notice_no_public_ipv6()
        return


    if eo_zones:
        eo_client = QcloudClient(secret=qcloud_secret, service='teo', version='2022-09-01')
        for zone in eo_zones:
            origin_groups = eo_client.describe_origin_group(zone)

            if len(origin_groups) >= 1:
                group_id = origin_groups[0].get('GroupId')
                records = set([i.get('Record') for i in origin_groups[0].get('Records')])

                if iptool.public_ipv6 == records:
                    logger.info(f"公网 IPV6 地址未发生变更，站点 {zone} 的源站组 {hostname} 无需更新。")
                else:
                    logger.info(f"公网 IPV6 地址发生变更，新的地址： {iptool.public_ipv6}")
                    error_msg, error_code = eo_client.modify_origin_group(zone, group_id, iptool.public_ipv6)
                    error_msg = F"成功更新站点 {zone} 的源站组 {hostname} 。" if not error_code and not error_msg else error_msg
                    logger.info(f"{error_msg} {error_code}")
                    dingtalk.notice_eo_result(hostname, zone, list(iptool.public_ipv6), error_msg)
            else:
                logger.info(f"站点 {zone} 的源站组 {hostname} 尚未未创建。")
                error_msg, error_code = eo_client.create_origin_group(zone, iptool.public_ipv6)
                error_msg = F"成功创建站点 {zone} 的源站组 {hostname} 。" if not error_code and not error_msg else error_msg
                logger.info(f"{error_msg} {error_code}")
                dingtalk.notice_eo_result(hostname, zone, list(iptool.public_ipv6), error_msg)

    if domains:
        dnspod = QcloudClient(secret=qcloud_secret, service='dnspod', version='2021-03-23')

        for domain in domains:
            sub_domain, record_type, top_domain = domain.split('|')
            fqdn = '.'.join([sub_domain, top_domain])
            records = dnspod.describe_dns_record(top_domain, sub_domain, record_type)
            record_counts = len(records)

            for record in records:
                if record["Value"] not in list(iptool.public_ipv6):
                    logger.info(f"站点 {fqdn} 存在已过期的解析记录 {record['Value']} , 正在删除。")
                    dnspod.delete_dns_record(top_domain, record['RecordId'])
                    record_counts -= 1

            if record_counts >= 1:
                logger.info(f"站点 {fqdn} 查询到至少存在一条有效解析记录, 跳过解析更改。")
            else:
                logger.info(f"站点 {fqdn} 不存在可用的解析记录，正在新建解析。")
                error_msg, error_code = dnspod.create_dns_record(top_domain, sub_domain, record_type, iptool.public_ipv6)
                error_msg = f"成功更新解解析记录 {fqdn} " if not error_code and not error_msg else error_msg
                logger.info(f"{error_msg} {error_code}")
                dingtalk.notice_dns_result(fqdn, list(iptool.public_ipv6), error_msg)


if __name__ == "__main__":
    main()
