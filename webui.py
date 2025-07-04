import streamlit as st
import yaml
import os

# 读取配置文件
def read_config():
    if os.path.exists("config.yaml"):
        with open("config.yaml", 'r', encoding='utf-8') as file:
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
    try:
        with open("config.yaml", 'w', encoding='utf-8') as file:
            yaml.dump(config, file, allow_unicode=True)
        st.success("配置文件保存成功！")
    except (yaml.YAMLError, IOError) as exc:
        st.error(f"无法保存配置文件: {exc}")

# Streamlit 主程序
def main():
    st.title("EdgeOne 配置管理")

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
    if st.button("添加 ZoneID"):
        if new_zone_id:
            if "EdgeOneZoneId" not in config:
                config["EdgeOneZoneId"] = []
            if new_zone_id not in config["EdgeOneZoneId"]:
                config["EdgeOneZoneId"].append(new_zone_id)
                save_config(config)
            else:
                st.warning("该 ZoneID 已存在。")
        else:
            st.warning("请输入有效的 ZoneID。")

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
    if st.button("添加 DnsPod 记录"):
        if new_sub_domain and new_record_type and new_top_domain:
            new_record = f"{new_sub_domain}|{new_record_type}|{new_top_domain}"
            if new_record not in dns_pod_records:
                dns_pod_records.append(new_record)
                config["DnsPodRecord"] = dns_pod_records
                save_config(config)
            else:
                st.warning("该 DnsPod 记录已存在。")
        else:
            st.warning("请输入有效的子域名、记录类型和顶级域名。")

    # 钉钉机器人配置
    st.header("钉钉机器人配置")
    dingtalk_webhook = st.text_input("DingTalkWebhook", value=config.get("DingTalkWebhook", ""))

    # 保存配置
    if st.button("保存配置"):
        config["TencentCloud"] = {
            "SecretId": secret_id,
            "SecretKey": secret_key
        }
        config["EdgeOneZoneId"] = edgeone_zone_ids
        config["DnsPodRecord"] = dns_pod_records
        config["DingTalkWebhook"] = dingtalk_webhook
        save_config(config)

if __name__ == "__main__":
    main()
