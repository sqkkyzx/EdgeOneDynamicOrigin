import requests
import subprocess


def get_ips(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        ip_list = response.text.strip().split('\n')
        return sorted(ip_list)  # 对获取的IP列表进行排序
    except requests.RequestException:
        return None


def read_previous_ips(filename):
    try:
        with open(filename, 'r') as file:
            ip_list = file.read().strip().split('\n')
            return sorted(ip_list)
    except FileNotFoundError:
        return None


def write_ips(filename, ips):
    with open(filename, 'w') as file:
        file.write('\n'.join(ips))


def check_rule_exists(name):
    cmd = f"netsh advfirewall firewall show rule name=\"{name}\""
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return name in result.stdout


def delete_firewall_rules(base_name):
    cmd = f"netsh advfirewall firewall delete rule name=\"{base_name}*\""
    subprocess.run(cmd, shell=True)


def add_firewall_rule(name, ips, protocol="TCP", direction="in", action="allow"):
    ips_str = ','.join(ips)
    cmd = f"netsh advfirewall firewall add rule name=\"{name}\" dir={direction} action={action} protocol={protocol} remoteip={ips_str}"
    subprocess.run(cmd, shell=True)


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
                    base_rule_name = f"@EdgeOne_{version}_{area}"
                    delete_firewall_rules(base_rule_name)

                    for i in range(0, len(ips), 200):
                        ip_group = ips[i:i+200]
                        rule_name = f"{base_rule_name}_Part_{i//200 + 1}"
                        add_firewall_rule(rule_name, ip_group)

                    write_ips(filename, ips)
                    changes_made = True

    return changes_made


if __name__ == "__main__":
    main()
