## Q1: Develop a Bash script that checks the syntax and validity of a JSON file according to a predefined schema or set of rules.

- without jq and Json Formatter
 ```
#!/bin/bash 

# Check if the file have been provided via argument
if [ -z "$1" ]; then
    echo "Error: File is required"
    exit 1
fi

file="$1"

#  set -x
extension=".json"

# Check if the file exists
if [ ! -f "$file" ]; then
    echo "Error: File does not exist!"
    exit 1
fi
#  set +x
# check if the file if empty
if [ ! -s "$file" ]; then 
    echo "Error: Schema failed -file is Empty"
    exit 1
fi
# check if the file is json format
if [[ "$file" == *"$extension" ]]; then
    echo "$file is a valid json file"
    cat "$file"
  fi
# Sample Rule, check that it doesn't have nested key/values
```
- With jq n Jsonformater

```
#!/bin/bash

# Check if file path is provided as an argument
if [ -z "$1" ]; then
  echo "Error: File path is required."
  exit 1
fi

# File path
file="$1"

# Check if the file exists
if [ ! -e "$file" ]; then
  echo "Error: File does not exist."
  exit 1
fi

# Check if jq and jsonschema are installed
if ! command -v jq > /dev/null || ! command -v jsonschema > /dev/null; then
  echo "Error: 'jq' and 'jsonschema' are required but not installed."
  exit 1
fi

# Define JSON schema file path
schema="/path/to/schema.json"

# Validate JSON file against schema using jsonschema
jsonschema -i "$file" "$schema"
exit_code=$?

if [ $exit_code -eq 0 ]; then
  echo "JSON file is valid against the schema."
else
  echo "JSON file is not valid against the schema."
fi

```

## Q2: Implement a Bash script that monitors the system log files in real-time, searches for specific keywords or patterns related to security events, and sends an alert via email or Slack when a match is found.
```
#!/bin/bash

# Define keywords or patterns to search for in log files
KEYWORDS=("error" "warning" "SW_UNKNOWN")

# Define log files to monitor
LOG_FILES=("/var/log/system.log" "/var/log/authd.log")

# Define email recipient and sender details
EMAIL_RECIPIENT="wingakmso@gmail.com"
EMAIL_SENDER="winniegakurumuthoni@gmail.com"
EMAIL_SUBJECT="Security Event Alert"

# Function to send email
send_email() {
    local message="$1"
    # echo  "Subject: $EMAIL_SUBJECT\nFrom: $EMAIL_SENDER\nTo: $EMAIL_RECIPIENT\n\n$message" | /usr/sbin/sendmail -t
    echo  "Subject: $EMAIL_SUBJECT\nFrom: $EMAIL_SENDER\nTo: $EMAIL_RECIPIENT\n\n$message" | /usr/sbin/sendmail -t
}

# Loop through the log files and monitor in real-time
for log_file in "${LOG_FILES[@]}"; do
    echo "Monitoring log file: $log_file"
    tail -f "$log_file" | while read -r line; do
        # Check for keywords or patterns in log lines
        for keyword in "${KEYWORDS[@]}"; do
            if echo "$line" | grep -q "$keyword"; then
                echo "Security event detected: $keyword"
                # Send alert via email
                send_email "Security event detected: $keyword\nLog file: $log_file\nLog line: $line"
                # Additional actions, such as sending Slack alerts, can be added here
            fi
        done
    done
done

```

## Q3: Write a Bash script that automates the process of encrypting and decrypting sensitive data using symmetric or asymmetric encryption algorithms, such as AES or RSA.
```
#!/bin/bash

# Generate a random encryption key
KEY=$(openssl rand -hex 32)

# Encrypt a file using AES
encrypt_file() {
  local file="$1"
  local encrypted_file="$file.enc"
  openssl enc -aes-256-cbc -in "$file" -out "$encrypted_file" -k "$KEY"
  echo "File $file encrypted successfully. Encrypted file: $encrypted_file"
}

# Decrypt a file using AES
decrypt_file() {
  local encrypted_file="$1"
  local decrypted_file="${encrypted_file%.enc}"
  openssl enc -aes-256-cbc -d -in "$encrypted_file" -out "$decrypted_file" -k "$KEY"
  echo "File $encrypted_file decrypted successfully. Decrypted file: $decrypted_file"
}

# Usage instructions
usage() {
  echo "Usage: $0 <encrypt|decrypt> <file>"
  echo "  encrypt: Encrypts the specified file using AES"
  echo "  decrypt: Decrypts the specified AES encrypted file"
}

# Main script logic
if [[ "$#" -ne 2 ]]; then
  usage
  exit 1
fi

operation="$1"
file="$2"

case "$operation" in
  encrypt)
    encrypt_file "$file"
    ;;
  decrypt)
    decrypt_file "$file"
    ;;
  *)
    usage
    exit 1
    ;;
esac
```

## Q4: Develop a Bash script that analyzes a Git repository(cloned locally) and identifies any sensitive information, such as passwords, API keys, or access tokens, stored in the code or configuration files.
```
#!/bin/bash

# Directory path of the Git repository
REPO_PATH="/Users/winniegakuru/Desktop/Projects/scripts"

# Sensitive keywords or patterns to search for
SENSITIVE_KEYWORDS=("password" "api_key" "access_token" "pssw")

# Search for sensitive keywords in code and configuration files
search_sensitive_info() {
  local path="$1"
  for keyword in "${SENSITIVE_KEYWORDS[@]}"; do
    echo "Searching for keyword: $keyword"
    grep -r "$keyword" "$path"
  done
}

# Main script logic
if [[ ! -d "$REPO_PATH" ]]; then
  echo "Error: Git repository not found at $REPO_PATH"
  exit 1
fi

echo "Analyzing Git repository: $REPO_PATH"
search_sensitive_info "$REPO_PATH"

```

## Q5: Implement a Bash script that scans a Linux server for security misconfigurations, such as weak file permissions, open network ports, or vulnerable software versions, and generates a report.
```
#!/bin/bash

# Output file for security report
OUTPUT_FILE="security_report.txt"

# Function to check file permissions
check_file_permissions() {
  local path="$1"
  echo "Checking file permissions: $path"
  find "$path" -type f -not -path "*/.git/*" -exec ls -l {} \; >> "$OUTPUT_FILE"
}

# Function to check open network ports
check_open_ports() {
  echo "Checking open network ports"
  netstat -tuln | grep "LISTEN" >> "$OUTPUT_FILE"
}

# Function to check installed software versions
check_installed_software_versions() {
  echo "Checking installed software versions"
  dpkg -l | grep "^ii" >> "$OUTPUT_FILE"
}

# Main script logic
echo "Security Scan Report" > "$OUTPUT_FILE"

# Check file permissions
 check_file_permissions "/"
#check_file_permissions "/Users/winniegakuru/Desktop/Projects/scripts"

# Check open network ports
check_open_ports

# Check installed software versions
check_installed_software_versions

echo "Security scan completed. Report saved to $OUTPUT_FILE"

```
## Q6: Write a Bash script that automates the process of creating and managing firewall rules on a Linux server to restrict incoming and outgoing network traffic based on predefined security policies.
- Linux

```
#!/bin/bash

# Define allowed incoming and outgoing network traffic rules
ALLOWED_INCOMING_PORTS=("22" "80" "443")  # Example: SSH, HTTP, HTTPS
ALLOWED_OUTGOING_PORTS=("53" "80" "443")  # Example: DNS, HTTP, HTTPS

# Function to create firewall rules for allowed incoming network traffic
create_incoming_rules() {
  for port in "${ALLOWED_INCOMING_PORTS[@]}"; do
    echo "Creating incoming rule for port $port"
    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
  done
}

# Function to create firewall rules for allowed outgoing network traffic
create_outgoing_rules() {
  for port in "${ALLOWED_OUTGOING_PORTS[@]}"; do
    echo "Creating outgoing rule for port $port"
    iptables -A OUTPUT -p tcp --dport "$port" -j ACCEPT
  done
}

# Function to enable firewall and block all other incoming and outgoing traffic
enable_firewall() {
  echo "Enabling firewall"
  iptables -P INPUT DROP
  iptables -P OUTPUT DROP
  iptables -P FORWARD DROP
}

# Function to disable firewall and allow all incoming and outgoing traffic
disable_firewall() {
  echo "Disabling firewall"
  iptables -P INPUT ACCEPT
  iptables -P OUTPUT ACCEPT
  iptables -P FORWARD ACCEPT
}

# Main script logic
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root."
  exit 1
fi

if [[ "$1" == "enable" ]]; then
  enable_firewall
  create_incoming_rules
  create_outgoing_rules
  echo "Firewall enabled with predefined rules."
elif [[ "$1" == "disable" ]]; then
  disable_firewall
  echo "Firewall disabled. All traffic allowed."
else
  echo "Usage: $0 [enable|disable]"
  exit 1
fi
```
- Mac-OS
```
#!/bin/bash

# Define allowed incoming and outgoing network traffic rules
ALLOWED_INCOMING_PORTS=("22" "80" "443")  # Example: SSH, HTTP, HTTPS
ALLOWED_OUTGOING_PORTS=("53" "80" "443")  # Example: DNS, HTTP, HTTPS

# Function to create firewall rules for allowed incoming network traffic
create_incoming_rules() {
  for port in "${ALLOWED_INCOMING_PORTS[@]}"; do
    echo "Creating incoming rule for port $port"
    sudo pfctl -q -a com.apple/800.CustomRules -f /dev/stdin <<< "block return-rst proto tcp from any to any port $port"
  done
}

# Function to create firewall rules for allowed outgoing network traffic
create_outgoing_rules() {
  for port in "${ALLOWED_OUTGOING_PORTS[@]}"; do
    echo "Creating outgoing rule for port $port"
    sudo pfctl -q -a com.apple/800.CustomRules -f /dev/stdin <<< "block return-rst proto tcp from any port $port to any"
  done
}

# Function to enable firewall and block all other incoming and outgoing traffic
enable_firewall() {
  echo "Enabling firewall"
  sudo pfctl -e
}

# Function to disable firewall and allow all incoming and outgoing traffic
disable_firewall() {
  echo "Disabling firewall"
  sudo pfctl -d
}

# Main script logic
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root."
  exit 1
fi

if [[ "$1" == "enable" ]]; then
  enable_firewall
  create_incoming_rules
  create_outgoing_rules
  echo "Firewall enabled with predefined rules."
elif [[ "$1" == "disable" ]]; then
  disable_firewall
  echo "Firewall disabled. All traffic allowed."
else
  echo "Usage: $0 [enable|disable]"
  exit 1
fi

```







