import json

def generate_iptables_rules(open_ports):
    rules = []
    for port in open_ports:
        rules.append(f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT")
    rules.append("iptables -A INPUT -j DROP")  # Default deny rule
    return rules

def generate_ufw_rules(open_ports):
    rules = []
    for port in open_ports:
        rules.append(f"ufw allow {port}/tcp")
    return rules

def generate_windows_firewall_rules(open_ports):
    rules = []
    for port in open_ports:
        rules.append(f"netsh advfirewall firewall add rule name=\"Allow Port {port}\" dir=in action=allow protocol=TCP localport={port}")
    return rules

def generate_firewall_rules(open_ports):
    print("\n[+] Generating Firewall Rules...")
    
    iptables_rules = generate_iptables_rules(open_ports)
    ufw_rules = generate_ufw_rules(open_ports)
    windows_rules = generate_windows_firewall_rules(open_ports)
    
    firewall_rules = {
        "iptables": iptables_rules,
        "ufw": ufw_rules,
        "windows_firewall": windows_rules
    }
    
    print(json.dumps(firewall_rules, indent=4))
    return firewall_rules

def run():
    open_ports = input("Enter open ports (comma-separated): ").strip()
    open_ports = [int(port) for port in open_ports.split(',') if port.isdigit()]
    
    if open_ports:
        rules = generate_firewall_rules(open_ports)
        
        with open("firewall_rules.json", "w") as f:
            json.dump(rules, f, indent=4)
        print("\n[+] Firewall rules saved to firewall_rules.json")
    else:
        print("[-] No valid ports provided.")

if __name__ == "__main__":
    run()
