import streamlit as st
import yaml
import os

# 读取配置文件
def read_config():
    if os.path.exists("../config.yaml"):
        with open("../config.yaml", 'r', encoding='utf-8') as file:
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
    with open("../config.yaml", 'w', encoding='utf-8') as file:
        try:
            yaml.dump(config, file, allow_unicode=True)
            st.success("配置文件保存成功！")
        except yaml.YAMLError as exc:
            st.error(f"无法保存配置文件: {exc}")

# 读取日志文件
def read_logs():
    log_file = "../log/log.txt"
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
def main():
    st.title("EdgeOne 配置管理")

    # 创建选项卡
    tab1, tab2 = st.tabs(["配置管理", "运行日志"])

    with tab1:
        # 读取当前配置
        config = read_config()

        # 腾讯云密钥配置
        st.header("腾讯云密钥配置")
        secret_id = st.text_input("SecretId", value=config.get("TencentCloud", {}).get("SecretId", ""))
        secret_key = st.text_input("SecretKey", value=config.get("TencentCloud", {}).get("SecretKey", ""), type="password")

        # EdgeOne 站点配置
        st.header("EdgeOne 站点配置")
        edgeone_zone_ids = st.multiselect("ZoneID", options=config.get("EdgeOneZoneId", []), default=config.get("EdgeOneZoneId", []))
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
                if st.button(f"删除", key=f"delete_{i}"):
                    dns_pod_records.remove(record)
                    config["DnsPodRecord"] = dns_pod_records
                    save_config(config)

        new_sub_domain = st.text_input("新增子域名")
        new_record_type = st.text_input("新增记录类型")
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

if __name__ == "__main__":
    main()
