import re
import tempfile
import uuid

import streamlit as st
import yaml
import os
from pathlib import Path
from eodo import task

v = "0.1.9"
home_dir = Path.home()
temp_dir = tempfile.gettempdir()

def run_task():
    task_id = str(uuid.uuid4())
    try:
        task.cron_logger.info(f"[{task_id}] 启动")
        task.main(task_id=task_id)
        task.cron_logger.info(f"[{task_id}] 结束")
    except Exception as e:
        print(e)
        task.cron_logger.error(f"[{task_id}] 异常")


def get_last_task_info():
    log_file = f"{temp_dir}/eodo.cron.log.txt"
    if os.path.exists(log_file):
        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        for line in reversed(lines):
            # 匹配 [uuid] 结束/异常/启动
            m = re.match(r".*\[([0-9a-f\-]{36})] 结束", line)
            if m:
                return {
                    "id": m.group(1),
                    "result": "结束",
                    "time": line[:19]
                }
            m = re.match(r".*\[([0-9a-f\-]{36})] 异常", line)
            if m:
                return {
                    "id": m.group(1),
                    "result": "异常",
                    "time": line[:19]
                }
            m = re.match(r".*\[([0-9a-f\-]{36})] 启动", line)
            if m:
                return {
                    "id": m.group(1),
                    "result": "启动",
                    "time": line[:19]
                }
        return {"id": "无", "result": "无", "time": "无"}
    else:
        return {"id": "无", "result": "无", "time": "无"}

def get_last_task_ipv6(task_id=""):
    log_file = f"{temp_dir}/eodo.task.log.txt"
    if os.path.exists(log_file):
        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        for line in reversed(lines):
            # 匹配 [uuid] 结束/异常/启动
            m = re.match(rF".*\[{task_id}] 获取公网 IPV6 地址成功，地址为：(.*)" , line)
            if m:
                return m.group(1)
        return "None"
    else:
        return "None"


# 读取配置文件
def read_config():
    if os.path.exists(f"{str(home_dir)}/.eodo.config.yaml"):
        with open(f"{str(home_dir)}/.eodo.config.yaml", 'r', encoding='utf-8') as file:
            try:
                config = yaml.safe_load(file)
            except yaml.YAMLError as exc:
                st.error(f"无法读取配置文件: {exc}")
                config = {}
    else:
        config = {}
    return config

# 保存配置文件
def save_config(config):
    with open(f"{str(home_dir)}/.eodo.config.yaml", 'w', encoding='utf-8') as file:
        try:
            yaml.dump(config, file, allow_unicode=True)
            st.success("配置文件保存成功！请手动刷新页面显示最新配置。")
        except yaml.YAMLError as exc:
            st.error(f"无法保存配置文件: {exc}")

# 读取日志文件
def read_logs():
    log_file = F"{temp_dir}/eodo.task.log.txt"
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                last_100_lines = lines[-100:]
                return ''.join(last_100_lines)
        except UnicodeDecodeError as ude:
            st.error(f"读取日志文件时出现编码错误：{ude}，请检查文件是否为 UTF-8 编码。")
        except Exception as e:
            st.error(f"读取日志文件时出现其他错误：{e}")
    return "日志文件不存在。"

# Streamlit 主程序
def main_ui():

    st.title(f"EdgeOne 动态源站管理 v{v}")

    # 创建选项卡
    tab0, tab1, tab2 = st.tabs(["状态", "配置", "日志"])

    with tab0:
        st.subheader("定时任务状态")
        info = get_last_task_info()
        st.write(f"上一次执行ID:")
        st.write(info.get("id", "无"))
        st.write(f"上一次执行结果:")
        st.write(info.get("result", "无"))
        st.write(f"上一次执行时间:")
        st.write(info.get("time", "无"))
        st.write(f"上一次获取地址: ")
        last_task_ipv6 = get_last_task_ipv6(info.get("id", "")) or "None"
        for ipv6 in last_task_ipv6.split(","):
            st.write(ipv6)
        st.write(f"当前定时间隔: {st.session_state.get('interval', '未知')} 分钟")
        st.button("刷新")
        if st.button("立即执行任务"):
            run_task()
            st.toast("任务已执行，请刷新页面查看日志", icon="✅")

    with tab1:
        # 读取当前配置
        config = read_config()

        # 腾讯云密钥配置
        st.header("腾讯云密钥配置")
        st.write("可以在 https://console.cloud.tencent.com/cam/capi 创建API密钥")
        secret_id = st.text_input("SecretId", value=config.get("TencentCloud", {}).get("SecretId", ""))
        secret_key = st.text_input("SecretKey", value=config.get("TencentCloud", {}).get("SecretKey", ""), type="password")
        if st.button("保存"):
            config["TencentCloud"] = {
                "SecretId": secret_id,
                "SecretKey": secret_key
            }
            save_config(config)

        # EdgeOne 站点配置
        st.header("EdgeOne 站点配置")
        st.write("ZoneID 在站点列表 https://console.cloud.tencent.com/edgeone/zones 查询")

        col1, col2 = st.columns([3, 1])
        with col1:
            st.write("ZoneID")
        with col2:
            st.write("操作")

        edgeone_zone_ids = config.get("EdgeOneZoneId", [])
        for i, zone_id in enumerate(config.get("EdgeOneZoneId", [])):
            with col1:
                st.write(zone_id)
            with col2:
                if st.button(f"删除", key=f"delete_zone_{i}"):
                    edgeone_zone_ids.remove(zone_id)
                    config["EdgeOneZoneId"] = edgeone_zone_ids
                    save_config(config)

        new_zone_id = st.text_input("新增 ZoneID")
        if st.button("添加 ZoneID") and new_zone_id:
            if "EdgeOneZoneId" not in config:
                config["EdgeOneZoneId"] = []
            config["EdgeOneZoneId"].append(new_zone_id)
            save_config(config)

        # DnsPod 记录配置
        st.header("DnsPod 记录配置")
        dns_pod_records = config.get("DnsPodRecord", [])

        # 显示表头
        col1, col2, col3, col4 = st.columns([2, 2, 2, 1])
        with col1:
            st.write("子域名")
        with col2:
            st.write("记录类型")
        with col3:
            st.write("顶级域名")
        with col4:
            st.write("操作")

        for i, record in enumerate(dns_pod_records):
            sub_domain, record_type, top_domain = record.split('|')
            col1, col2, col3, col4 = st.columns([2, 2, 2, 1])
            with col1:
                st.write(sub_domain)
            with col2:
                st.write(record_type)
            with col3:
                st.write(top_domain)
            with col4:
                if st.button(f"删除", key=f"delete_domain_{i}"):
                    dns_pod_records.remove(record)
                    config["DnsPodRecord"] = dns_pod_records
                    save_config(config)

        new_sub_domain = st.text_input("新增子域名")
        new_record_type = st.text_input("新增记录类型", value="AAAA")
        new_top_domain = st.text_input("新增顶级域名")
        if st.button("添加 DnsPod 记录") and new_sub_domain and new_record_type and new_top_domain:
            new_record = f"{new_sub_domain}|{new_record_type}|{new_top_domain}"
            if new_record not in dns_pod_records:
                dns_pod_records.append(new_record)
                config["DnsPodRecord"] = dns_pod_records
                save_config(config)

        # 钉钉机器人配置
        st.header("钉钉机器人配置")
        dingtalk_webhook = st.text_input("DingTalkWebhook", value=config.get("DingTalkWebhook", ""))

        # 保存配置
        if st.button("保存所有配置"):
            config["TencentCloud"] = {
                "SecretId": secret_id,
                "SecretKey": secret_key
            }
            config["EdgeOneZoneId"] = edgeone_zone_ids
            config["DnsPodRecord"] = dns_pod_records
            config["DingTalkWebhook"] = dingtalk_webhook
            save_config(config)

    with tab2:
        logs = read_logs()
        st.code(logs, language="plaintext")

def main_entry():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interval', type=int, default=15, help='定时间隔（分钟）')
    args = parser.parse_args()
    st.session_state.interval = args.interval
    st.set_page_config(page_title="EdgeOneDynamicOrigin")
    main_ui()

if __name__ == "__main__":
    main_entry()
