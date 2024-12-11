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


def delete_firewall_rules(group="@用户定义_EdgeOne"):
    cmd = f"PowerShell -Command \"Remove-NetFirewallRule -Group '{group}'\""
    subprocess.run(cmd, shell=True)


def add_firewall_rule(name, ips, protocol="TCP", direction="Inbound", action="ALLOW", group="@用户定义_EdgeOne"):
    ips_str = '","'.join(ips)
    cmd = f"PowerShell -Command \"New-NetFirewallRule -DisplayName '{name}' -Direction {direction} -Action {action.capitalize()} -Protocol {protocol} -RemoteAddress \"{ips_str}\" -Group '{group}'\""
    subprocess.run(cmd, shell=True)


def main():
    ip_versions = ['v4', 'v6']
    areas = ['mainland-china', 'overseas']
    changes_made = False

    set_list = {}

    for version in ip_versions:
        for area in areas:
            url = f"https://api.edgeone.ai/ips?version={version}&area={area}"
            ips = get_ips(url)
            if ips:
                base_rule_name = f"{version}_{area}"
                set_list[base_rule_name] = ips

                filename = f"{base_rule_name}_ips.txt"
                previous_ips = read_previous_ips(filename)
                if ips != previous_ips:
                    changes_made = True
    if changes_made:
        delete_firewall_rules()
        for base_rule_name, ips in set_list.items():
            for i in range(0, len(ips), 200):
                ip_group = ips[i:i + 200]
                rule_name = f"EdgeOne_{base_rule_name}_Part_{i // 200 + 1}"
                add_firewall_rule(rule_name, ip_group)
            write_ips(f"{base_rule_name}_ips.txt", ips)

    return changes_made


if __name__ == "__main__":
    main()
