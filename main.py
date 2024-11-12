import hashlib
import hmac
import json
import logging
import socket
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

import requests
import yaml


def setup_logging():
    """
    设置日志记录。
    """
    _logger = logging.getLogger()
    _logger.setLevel(logging.INFO)

    file_handler = RotatingFileHandler("eodo.log", maxBytes=200 * 1024, backupCount=1)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    _logger.addHandler(file_handler)
    _logger.addHandler(console_handler)

    return _logger


# 腾讯云请求信息
service: str = 'teo'
host: str = 'teo.tencentcloudapi.com'
endpoint: str = 'https://' + host
version: str = '2022-09-01'
algorithm: str = 'TC3-HMAC-SHA256'
content_type: str = 'application/json; charset=utf-8'
http_request_method: str = 'POST'
canonical_uri: str = '/'
canonical_query_string: str = ''
signed_headers: str = 'content-type;host;x-tc-action'

logger = setup_logging()


def read_config(node):
    with open('config.yaml', 'r', encoding='utf-8') as file:
        try:
            config = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            logging.error(f"Error reading YAML file: {exc}")
    return config.get(node, {})


def v6ping_test(ipv6):
    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0',
        'referer': 'https://ipw.cn/ipv6ping/'
    }
    res = requests.get(F'https://ipw.cn/api/ping/ipv6/{ipv6}/4/all', headers=headers)
    if 'PingFailed' in res.text:
        logger.info(f"Address [{ipv6}] Ping Failed...")
        return False
    logger.info(f"Address [{ipv6}] Ping Success...")
    return True


def get_ipv6_addresses():
    """
    从指定网络接口获取首选IPv6地址列表。
    """
    addr_infos = socket.getaddrinfo(socket.gethostname(), None)
    ipv6_list = [addr_info[4][0] for addr_info in addr_infos if addr_info[0] == socket.AF_INET6 and addr_info[4][3] == 0]
    count = len(ipv6_list)
    if count > 0:
        logger.info(f"There are {len(ipv6_list)} IPv6 addresses, waiting for Ping Test...")
        ipv6_list = [v6 for v6 in ipv6_list if v6ping_test(v6)]
        logger.info(f"IPv6: {ipv6_list}")
    else:
        logger.info(f"No IPv6 addresses.")
    return ipv6_list


def get_ipv4_addresses():
    """
    从指定网络接口获取首选IPv4地址列表。
    """
    ipv4 = requests.get('https://4.ipw.cn').text
    return ipv4.split('\n')


def eo_api(action, body):
    secret = read_config('TencentCloud')
    secret_id, secret_key = secret.get("SecretId"), secret.get("SecretKey")

    timestamp: int = int(time.time())
    date: str = datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d')

    payload = json.dumps(body)

    hashed_request_payload: str = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    canonical_headers: str = f'content-type:{content_type}\nhost:{host}\nx-tc-action:{action.lower()}\n'
    canonical_request: str = (http_request_method + '\n' +
                              canonical_uri + '\n' +
                              canonical_query_string + '\n' +
                              canonical_headers + '\n' +
                              signed_headers + '\n' +
                              hashed_request_payload)

    # 拼接待签名字符串
    credential_scope = f'{date}/{service}/tc3_request'
    hashed_canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    string_to_sign = f"{algorithm}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}"

    # 计算签名
    def sign(key, message):
        return hmac.new(key, message.encode('utf-8'), hashlib.sha256).digest()

    secret_date = sign(('TC3' + secret_key).encode('utf-8'), date)
    secret_service = sign(secret_date, service)
    secret_signing = sign(secret_service, 'tc3_request')
    signature = hmac.new(secret_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    authorization = (f'{algorithm} '
                     f'Credential={secret_id}/{credential_scope}, '
                     f'SignedHeaders={signed_headers}, '
                     f'Signature={signature}')
    # 发送请求
    headers = {
        'Authorization': authorization,
        'Content-Type': content_type,
        'Host': host,
        'X-TC-Action': action,
        'X-TC-Version': version,
        'X-TC-Timestamp': str(timestamp)
    }

    return requests.post(endpoint, headers=headers, data=payload)


def modify_origin_group(zone_id, origin_group_id, iplist):
    body = {
        "ZoneId": zone_id,
        "GroupId": origin_group_id,
        "Records": [{"Record": ip, "Type": "IP_DOMAIN", "Weight": 100} for ip in iplist]
    }
    return eo_api('ModifyOriginGroup', body).json()


def describe_origin_group(zone_id, origin_group_id):
    body = {"ZoneId": zone_id, "Filters": [{"Name": "origin-group-id", "Values": [origin_group_id]}]}
    res = eo_api('DescribeOriginGroup', body).json().get('Response', {}).get('OriginGroups', {})

    if len(res) >= 1:
        origin_records = res[0].get('OriginRecords')
        iplist = [i.get('Record') for i in origin_records]
        return iplist
    else:
        logger.error(f"OriginGroup does not exist. <{zone_id}:{origin_group_id}>")
        return None


def main():
    groups = read_config("EdgeOne")
    dingtalk = read_config("DingTalk")
    ipv6_list = get_ipv6_addresses()
    ipv4_list = get_ipv4_addresses()

    if not ipv6_list:
        logger.info(f"Cannot Get IPv6 address, Skip update all OriginGroup.")
        if dingtalk:
            webhook_url = dingtalk.get("webhook")
            requests.post(webhook_url, json={
                "markdown": {
                    "title": dingtalk.get('title'),
                    "text": f"### EdgeOne源站更新\n\n"
                            f"> 信息：无法获取公网IPv6，跳过此次更新。"
                }, "msgtype": "markdown"})

        return

    for item in groups:
        zone, og, tag = item.get('ZoneId'), item.get('OriginGroupId'), item.get('Tag')

        if ipv6_list == describe_origin_group(zone, og):
            logger.info(f"IP address unchanged, OriginGroup {tag} no update needed.")
            continue
        else:
            logger.info(f"IP address changed, New IP <{ipv6_list}>")
        res = modify_origin_group(zone, og, ipv6_list)
        error = res.get("Response", {}).get("Error", {})
        msg, error_code = error.get("Message", ""), error.get("Code", "")

        if not error_code and not msg:
            msg = F"Successfully updated the OriginGroup {tag}"

        logger.info(f"{error_code}:{msg}")

        if dingtalk:
            webhook_url = dingtalk.get("webhook")
            requests.post(webhook_url, json={
                "markdown": {
                    "title": dingtalk.get('title'),
                    "text": f"### EdgeOne源站更新\n\n"
                            f"> 标签：{tag}\n\n"
                            f"> 站点：{zone}\n\n"
                            f"> 源站组：{og}\n\n"
                            f"> IPV6：{ipv6_list}\n\n"
                            f"> IPV4：{ipv4_list}\n\n"
                            f"> 信息：{msg}"
                }, "msgtype": "markdown"})
    return


if __name__ == "__main__":
    main()
