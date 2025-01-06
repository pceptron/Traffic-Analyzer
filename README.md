# Traffic Analyzer

The `traffic_analyzer.py` script is designed to monitor and analyze network traffic on specified interfaces. It captures packets, aggregates traffic statistics, and performs WHOIS lookups to provide detailed information about external IP addresses. This tool is useful for network administrators who need to monitor traffic patterns and identify external connections.

## Features

- **Packet Capture**: Uses Scapy to capture network packets on specified interfaces.
- **Traffic Aggregation**: Aggregates traffic data by source and destination IP addresses.
- **WHOIS Lookup**: Performs WHOIS lookups to gather information about external IP addresses, including network name, country, and CIDR.
- **Configurable**: Uses a YAML configuration file to specify client IPs, router IP, VPN server IP, and other settings.
- **Logging**: Logs traffic statistics and analysis results to specified files.

## Configuration

The script relies on a configuration file located at `/opt/scripts/config.yaml`. This file should contain the following settings:

```yaml
CLIENT_IPS:
  - 192.168.1.0/24
  - 10.0.0.0/8
RTIMER: 300
ROUTER_IP: 192.168.1.1
VPN_SERVER_IP: 10.8.0.1
TRAFFIC_STAT_FILE: /tmp/traffic_stat.log
ANALYSIS_FILE_TEMPLATE: /tmp/traffic_analysis_{timestamp}.log
```

### Key Configuration Options

- **CLIENT_IPS**: List of client IP networks to monitor.
- **RTIMER**: Rotation timer in seconds for traffic analysis cycles.
- **ROUTER_IP**: IP address of the router.
- **VPN_SERVER_IP**: IP address of the VPN server.
- **TRAFFIC_STAT_FILE**: Path to the file where traffic statistics are logged.
- **ANALYSIS_FILE_TEMPLATE**: Template for the analysis output file, with a timestamp placeholder.

## Usage

1. **Setup**: Ensure the script is executable and the configuration file is correctly set up.
2. **Execution**: Run the script using Python 3:
   ```bash
   python3 traffic_analyzer.py
   ```
3. **Monitoring**: The script will continuously monitor traffic, log statistics, and perform periodic analysis based on the rotation timer.

## Logging

- **Traffic Statistics**: Logged to the file specified in `TRAFFIC_STAT_FILE`.
- **Analysis Results**: Saved to files based on the `ANALYSIS_FILE_TEMPLATE`, with a timestamp for each analysis cycle.

## Error Handling

- **WHOIS Errors**: Logs errors if WHOIS lookups fail.
- **Unexpected Errors**: Catches and logs any unexpected exceptions.

## Dependencies

- **Python 3**
- **Scapy**: For packet capturing and analysis.
- **PyYAML**: For reading the YAML configuration file.

## Installation

1. Install Python 3 and required packages:
   ```bash
   sudo apt-get install python3
   pip install scapy pyyaml
   ```

2. Place the script in the desired directory and make it executable:
   ```bash
   chmod +x traffic_analyzer.py
   ```

3. Ensure the configuration file is correctly set up at `/opt/scripts/config.yaml`.

## License

This project is licensed under the MIT License.

---

This README provides a comprehensive overview of the script's functionality, configuration, and usage. Adjust the paths and details as necessary to fit your specific setup and requirements.
