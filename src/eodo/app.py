import argparse
import os
import hashlib
import hmac
import threading
import uuid
import time
import json
import logging
import socket
import re
import psutil
import ipaddress
import tempfile
import requests
import yaml
from pathlib import Path
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import List

from fastapi import FastAPI, BackgroundTasks, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn


# =================== 常量与路径 ===================
HOME_DIR = Path.home()
TEMP_DIR = tempfile.gettempdir()
CURRENT_DIR = Path(__file__).parent
STATIC_PATH = CURRENT_DIR / "static"
STATIC_PATH.mkdir(exist_ok=True)
print(STATIC_PATH)
print(TEMP_DIR)


# =================== 日志与配置 ===================
def setup_logging(file="task"):
    """日志初始化"""
    _logger = logging.getLogger(f"task.{file}")
    _logger.setLevel(logging.INFO)

    log_file = f"{TEMP_DIR}/eodo.{file}.log.txt"
    file_handler = RotatingFileHandler(log_file, maxBytes=200 * 1024, backupCount=1, encoding="utf-8")
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

    for handler in [file_handler, console_handler]:
        handler.setFormatter(formatter)
        handler.setLevel(logging.INFO)
        if not _logger.hasHandlers():
            _logger.addHandler(handler)
    return _logger

logger = setup_logging("task")
cron_logger = setup_logging("cron")

def get_hostname():
    """获取合法主机名"""
    pattern = r'[^a-zA-Z0-9_-]'
    name = socket.gethostname().lower()
    if re.search(pattern, name):
        raise ValueError("主机名包含不允许的字符")
    return name

hostname = get_hostname()

def read_config():
    """读取YAML配置"""
    config_path = f"{str(HOME_DIR)}/.eodo.config.yaml"
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except Exception as exc:
        logger.error(f"配置文件读取失败: {exc}")
        return {}


# =================== 腾讯云API类 ===================
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


# =================== 工具类 ===================
class IPv6Tool:
    def __init__(self, select_iface="", task_id=""):
        self.task_id = task_id
        self.public_ipv6:set[str]|None = self.get_ipv6_list(select_iface)

    def get_ipv6_list(self, select_iface=""):
        ipv6_list = []
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            if select_iface and iface != select_iface:
                continue
            for addr in addr_list:
                ip = addr.address.split('%')[0]
                if addr.family == socket.AF_INET6 and self.is_public_ipv6(ip):
                    if self.public_ipv6_check(ip):
                        ipv6_list.append(ip)
                    else:
                        continue

        if not ipv6_list:
            return None
        else:
            return set(sorted(ipv6_list))

    @staticmethod
    def is_public_ipv6(ip):
        try:
            addr = ipaddress.IPv6Address(ip)
            return not (addr.is_link_local or addr.is_private or addr.is_loopback or addr.is_unspecified)
        except ValueError:
            return False  # 非法IP，就认为不是公网

    def public_ipv6_check(self, ip):
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36 Edg/89.0.774.54"

        def ipw_cn():
            try:
                res = requests.get(
                    f"https://ipw.cn/api/ping/ipv6/{ip}/1/all",
                    headers={"User-Agent": user_agent},
                    timeout=5
                )
                if '"lossPacket":0' in res.text:
                    logger.info(f"[{self.task_id}] ipw.cn Ping {ip} 无丢包")
                    return True
                else:
                    logger.info(f"[{self.task_id}] ipw.cn Ping {ip} 超时")
                    return False
            except Exception as e:
                logger.debug(e)
                logger.info(f"[{self.task_id}] ipw.cn Ping {ip} 超时或异常")
                return False
        def ping6_network():
            try:
                res = requests.get(
                    f"https://ping6.network/index.php?host={ip.replace(":", "%3A")}",
                    headers={"User-Agent": user_agent},
                    timeout=15
                )
                if ', 0% packet loss' in res.text:
                    logger.info(f"[{self.task_id}] ping6.network Ping [{ip}] 无丢包")
                    return True
                else:
                    logger.info(f"[{self.task_id}] ping6.network Ping {ip} 超时")
                    return False
            except Exception as e:
                logger.debug(e)
                logger.info(f"[{self.task_id}] ping6.network Ping {ip} 超时或异常")
                return False

        return True if ipw_cn() else ping6_network()


# =================== 钉钉通知类 ===================
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

# =================== 任务处理 ===================
def update_task(task_id=""):
    config = read_config()
    iptool = IPv6Tool(config.get("SelectIface"), task_id)
    dingtalk = Dingtalk(config.get('DingTalkWebhook'))
    eo_zones = config.get("EdgeOneZoneId")
    domains = config.get('DnsPodRecord')
    qcloud_secret = config.get('TencentCloud')

    if not iptool.public_ipv6:
        logger.info(f"[{task_id}] 无法获取 IPV6 地址，跳过后续所有步骤。")
        dingtalk.notice_no_public_ipv6()
        return
    else:
        logger.info(f"[{task_id}] 获取公网 IPV6 地址成功，地址为：{",".join(iptool.public_ipv6)}")

    if eo_zones:
        eo_client = QcloudClient(secret=qcloud_secret, service='teo', version='2022-09-01')
        for zone in eo_zones:
            origin_groups = eo_client.describe_origin_group(zone)

            if len(origin_groups) >= 1:
                group_id = origin_groups[0].get('GroupId')
                old_list = [i.get('Record') for i in origin_groups[0].get('Records')]
                old_list.sort()
                records = set(old_list)

                if iptool.public_ipv6 == records:
                    logger.info(f"[{task_id}] 公网 IPV6 地址未发生变更，站点 {zone} 的源站组 {hostname} 无需更新。")
                else:
                    logger.info(f"[{task_id}] 公网 IPV6 地址发生变更，新的地址： {iptool.public_ipv6}")
                    error_msg, error_code = eo_client.modify_origin_group(zone, group_id, iptool.public_ipv6)
                    error_msg = F"成功更新站点 {zone} 的源站组 {hostname} 。" if not error_code and not error_msg else error_msg
                    logger.info(f"[{task_id}] {error_msg} {error_code}")
                    dingtalk.notice_eo_result(hostname, zone, list(iptool.public_ipv6), error_msg)
            else:
                logger.info(f"[{task_id}] 站点 {zone} 的源站组 {hostname} 尚未未创建。")
                error_msg, error_code = eo_client.create_origin_group(zone, iptool.public_ipv6)
                error_msg = F"成功创建站点 {zone} 的源站组 {hostname} 。" if not error_code and not error_msg else error_msg
                logger.info(f"[{task_id}] {error_msg} {error_code}")
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
                    logger.info(f"[{task_id}] 站点 {fqdn} 存在已过期的解析记录 {record['Value']} , 正在删除。")
                    dnspod.delete_dns_record(top_domain, record['RecordId'])
                    record_counts -= 1

            if record_counts >= 1:
                logger.info(f"[{task_id}] 站点 {fqdn} 查询到至少存在一条有效解析记录, 跳过解析更改。")
            else:
                logger.info(f"[{task_id}] 站点 {fqdn} 不存在可用的解析记录，正在新建解析。")
                error_msg, error_code = dnspod.create_dns_record(top_domain, sub_domain, record_type, iptool.public_ipv6)
                error_msg = f"成功更新解解析记录 {fqdn} " if not error_code and not error_msg else error_msg
                logger.info(f"[{task_id}] {error_msg} {error_code}")
                dingtalk.notice_dns_result(fqdn, list(iptool.public_ipv6), error_msg)

last_status = {"id":"", "result":"等待"}

def run_task_in_background():
    task_id = str(uuid.uuid4())
    try:
        cron_logger.info(f"[{task_id}] 启动")
        update_task(task_id=task_id)
        cron_logger.info(f"[{task_id}] 结束")
        last_status.update({"id": task_id, "result": "结束"})
    except Exception as e:
        logger.debug(e)
        cron_logger.error(f"[{task_id}] 异常")
        last_status.update({"id": task_id, "result": "异常"})

def load_interval(default_interval=15):
    cfgfile = os.path.join(str(HOME_DIR), ".eodo.config.yaml")
    if os.path.exists(cfgfile):
        with open(cfgfile, "r", encoding="utf-8") as f:
            try:
                config = yaml.safe_load(f)
                interval = int(config.get("IntervalMin", 15))
                if interval < 1: interval = 1
                return interval
            except Exception as e:
                logger.debug(e)
    return default_interval  # 默认值

class TaskScheduler:
    def __init__(self, interval_min=15):
        self.interval_min = interval_min
        self.scheduler_thread = None
        self.scheduler_stop_flag = threading.Event()
        self.lock = threading.Lock()

    def scheduler_loop(self):
        while not self.scheduler_stop_flag.is_set():
            run_task_in_background()
            for _ in range(self.get_interval() * 60):
                if self.scheduler_stop_flag.is_set():
                    return
                time.sleep(1)

    def get_interval(self):
        with self.lock:
            return self.interval_min

    def set_interval(self, interval_min):
        if interval_min < 1:
            interval_min = 1
        with self.lock:
            self.interval_min = interval_min

    def start_scheduler(self):
        if self.scheduler_thread is None or not self.scheduler_thread.is_alive():
            self.scheduler_thread = threading.Thread(target=self.scheduler_loop, daemon=True)
            self.scheduler_thread.start()

    def restart_scheduler(self, interval_min):
        self.scheduler_stop_flag.set()
        self.scheduler_thread = None
        self.set_interval(interval_min)
        self.scheduler_stop_flag.clear()
        self.start_scheduler()

# 声明全局定时器
scheduler:TaskScheduler


# =================== FastAPI 路由 ===================
app = FastAPI()


@app.get("/", response_class=HTMLResponse)
async def read_root():
    return FileResponse(str(STATIC_PATH / "index.html"))

# 提供静态文件服务
app.mount("/static", StaticFiles(directory=str(STATIC_PATH)), name="static")


@app.get('/api/status')
def api_status():
    # 简单读取
    log_file = f"{TEMP_DIR}/eodo.cron.log.txt"
    if not os.path.exists(log_file):
        return last_status
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in reversed(f.readlines()):
            if "] " in line:
                tid = line.split("]")[0].split("[")[-1]
                if "异常" in line:
                    return {"id": tid, "result": "异常", "time": line[:19]}
                if "结束" in line:
                    return {"id": tid, "result": "结束", "time": line[:19]}
                if "启动" in line:
                    return {"id": tid, "result": "启动", "time": line[:19]}
    return last_status

@app.post('/api/run-task')
def api_run(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_task_in_background)
    return {"msg": "已触发"}

@app.get('/api/iface')
def api_iface():
    return list(psutil.net_if_addrs().keys())

@app.get('/api/config')
def get_config():
    cfgfile = os.path.join(str(HOME_DIR), ".eodo.config.yaml")
    if not os.path.exists(cfgfile):
        return {}
    with open(cfgfile, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

@app.post('/api/config')
async def post_config(request: Request):
    data = await request.json()
    cfgfile = os.path.join(str(HOME_DIR), ".eodo.config.yaml")
    # 允许配置 IntervalMin
    interval = data.get("IntervalMin", None)
    with open(cfgfile, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True)
    # 如果带了 IntervalMin，同步到调度器
    if interval is not None:
        try:
            scheduler.restart_scheduler(int(interval))
        except Exception as e:
            logger.debug(e)
    return {"msg": "配置已保存"}

@app.get('/api/logs')
def get_logs():
    log_file = f"{TEMP_DIR}/eodo.task.log.txt"
    if os.path.exists(log_file):
        lines = open(log_file, encoding="utf-8").readlines()[-100:]
        return {"logs": "".join(lines)}
    return {"logs": ""}

@app.post('/api/interval')
async def set_interval(request: Request):
    data = await request.json()
    val = int(data.get("interval", 15))
    if val < 1: val = 1
    # 修改调度器周期
    scheduler.restart_scheduler(val)
    # 保存到配置文件
    cfgfile = os.path.join(str(HOME_DIR), ".eodo.config.yaml")
    config = {}
    if os.path.exists(cfgfile):
        with open(cfgfile, "r", encoding="utf-8") as f:
            try:
                config = yaml.safe_load(f) or {}
            except Exception as e:
                logger.debug(e)
                config = {}
    config["IntervalMin"] = val
    with open(cfgfile, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True)
    return {"msg": "已设置周期间隔"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=54321, help='Web UI 端口')

    args = parser.parse_args()
    global scheduler
    scheduler = TaskScheduler(interval_min=load_interval())
    scheduler.start_scheduler()
    uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
