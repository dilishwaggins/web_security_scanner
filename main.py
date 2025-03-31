import argparse
from modules.web_app_scanner import run as run_web_app_scanner
from modules.firewall_rule_generator import run as run_firewall_rule_generator
from modules.hash_calculator import run as run_hash_calculator

def main():
    parser = argparse.ArgumentParser(description="Web Security Scanner Toolkit")
    parser.add_argument("--scanner", help="Run the Web App Scanner", action="store_true")
    parser.add_argument("--firewall", help="Generate Firewall Rules", action="store_true")
    parser.add_argument("--hash", help="Calculate File Hashes", action="store_true")
    
    args = parser.parse_args()
    
    if args.scanner:
        run_web_app_scanner()
    elif args.firewall:
        run_firewall_rule_generator()
    elif args.hash:
        run_hash_calculator()
    else:
        print("\nUsage: python main.py --scanner | --firewall | --hash")
        print("\nOptions:")
        print("  --scanner    Run Web App Scanner")
        print("  --firewall   Generate Firewall Rules")
        print("  --hash       Calculate File Hashes")

if __name__ == "__main__":
    main()
