# CVExplorer: 
Uncover vulnerabilities by discovering assigned CVEs to IPs, empowering you to fortify your security posture with a single glance into the digital landscape.

## Overview

CVExplorer is a powerful tool designed to uncover vulnerabilities by discovering assigned CVEs (Common Vulnerabilities and Exposures) to IPs using the Shodan API. This tool empowers users to fortify their security posture with a single glance into the digital landscape, providing valuable insights into potential security risks associated with specific IPs.

## Features

- **IP-CVE Mapping:** Quickly identify and explore assigned CVEs for a given IP address.
- **Domain-based Scan:** Perform scans based on a list of domains to retrieve and analyze CVE data.
- **Multi-threaded Scanning:** Utilize multi-threading for efficient and fast asset discovery.
- **CSV Report Generation:** Generate individual CSV reports for each discovered IP, making it easy to analyze and share findings.
- **User-friendly Interface:** Command-line interface with informative color-coded output for a better user experience.

## Prerequisites

Before using the Shodan CVE Explorer, ensure that you have:

- Python 3.x installed on your system.
- Shodan API key. Get your API key by signing up on the [Shodan website](https://www.shodan.io/) and following the instructions.

## Installation

   ```bash
   git clone https://github.com/umsvishal/CVExplorer.git
   cd CVExplorer
   pip3 install -r requirements.txt
  ```
## Configure Shodan API key:
Open the .env file and replace API_Key with your actual Shodan API key.
```
API_Key=<Your Shodan API Key>
```

## Usage
Run the tool with the desired options:
```
python3 cve_explorer.py -f domain_list.txt
or
python3 cve_explorer.py -d example.com
```

## Output
The tool generates individual CSV reports for each discovered IP in the Output directory. These reports contain information about assigned CVEs for the corresponding IP.
![Alt text](https://github.com/umsvishal/CVExplorer/blob/main/Screenshot%202023-12-22%20at%2011.24.05%20PM.png)

## Contributing
If you find any issues or have suggestions for improvement, feel free to open an issue or submit a pull request. Your contributions are welcome!

