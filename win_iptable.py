import requests
import subprocess


def get_ips(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        ip_list = response.text.strip().split('\n')
        return ','.join(ip_list)
    except requests.RequestException:
        return None


def read_previous_ips(filename):
    try:
        with open(filename, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        return None


def write_ips(filename, ips):
    with open(filename, 'w') as file:
        file.write(ips)


def check_rule_exists(name):
    cmd = f"netsh advfirewall firewall show rule name=\"{name}\""
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return name in result.stdout


def update_firewall_rule(name, ips, protocol="TCP", direction="in", action="allow"):
    delete_cmd = f"netsh advfirewall firewall delete rule name=\"{name}\""
    add_cmd = f"netsh advfirewall firewall add rule name=\"{name}\" dir={direction} action={action} protocol={protocol} remoteip={ips}"
    subprocess.run(delete_cmd, shell=True)  # 删除旧规则
    subprocess.run(add_cmd, shell=True)  # 添加新规则


def add_firewall_rule(name, ips, protocol="TCP", direction="in", action="allow"):
    cmd = f"netsh advfirewall firewall add rule name=\"{name}\" dir={direction} action={action} protocol={protocol} remoteip={ips}"
    subprocess.run(cmd, shell=True)  # 创建规则


def main():
    ip_versions = ['v4', 'v6']
    areas = ['mainland-china', 'overseas']
    changes_made = False

    for version in ip_versions:
        for area in areas:
            url = f"https://api.edgeone.ai/ips?version={version}&area={area}"
            ips = get_ips(url)
            if ips:
                filename = f"{version}_{area}_ips.txt"
                previous_ips = read_previous_ips(filename)
                if ips != previous_ips:
                    rule_name = f"@EdgeOne_{version}_{area}"
                    if check_rule_exists(rule_name):
                        update_firewall_rule(rule_name, ips)
                    else:
                        add_firewall_rule(rule_name, ips)
                    write_ips(filename, ips)
                    changes_made = True

    return changes_made


if __name__ == "__main__":
    main()
