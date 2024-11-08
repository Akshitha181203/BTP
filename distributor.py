import threading
import re
import json
import os

# Define directories for logs and rules
RAW_LOG_DIR = './raw_logs'
PARSED_LOG_DIR = './parsed_logs'
RULES_DIR = {
    'network': '/Network/rules',
    'application': '/Application/rules',
    'system': '/System/rules'
}
OUTPUT_DIR = './output'

# Function to parse raw logs into a structured format
def parse_logs_with_logparser(line, log_type):
    # Parse the logs using log parser or create one
    return None

# Function to parse and save parsed logs
def parse_logs(log_type):
    parsed_logs = parse_logs_with_logparser(log_type)
    
    # Save parsed logs to a file
    if parsed_logs:
        parsed_log_file_path = os.path.join(PARSED_LOG_DIR, f"{log_type}_logs.json")
        with open(parsed_log_file_path, 'w') as f:
            json.dump(parsed_logs, f, indent=4)
        print(f"Parsed logs saved to {parsed_log_file_path}")
    else:
        print(f"No parsed logs for {log_type}")

# Function to load rules from a directory
def load_rules(rule_dir):
    rules = []
    for file in os.listdir(rule_dir):
        if file.endswith(".json"):
            with open(os.path.join(rule_dir, file), 'r') as f:
                rules.append(json.load(f))
    return rules

# Function to apply rules on parsed logs
def apply_rules(logs, rules, log_type):
    attacked_logs = []

    # Write rules according to the type of rule
    
    if re.search(rule["condition"], log["message"]):
        log["Alert"] = rule["alert_message"]
        log["Stage"] = rule.get("stage", "Unknown")
        log["Technique"] = rule.get("technique", "Unknown")
        attacked_logs.append(log)
    return attacked_logs

# Function to process logs of a specific type
def process_logs(log_type):
    # Parse raw logs
    parse_logs(log_type)

    # Load rules
    rules = load_rules(RULES_DIR[log_type])
    
    # Load parsed logs for the log_type
    parsed_log_file_path = os.path.join(PARSED_LOG_DIR, f"{log_type}_logs.json")
    with open(parsed_log_file_path, 'r') as f:
        logs = json.load(f)
    
    # Apply rules to logs
    attacked_logs = apply_rules(logs, rules, log_type)
    
    # Save the attacked logs
    output_file_path = os.path.join(OUTPUT_DIR, f"{log_type}_attacked_logs.json")
    with open(output_file_path, 'w') as f:
        json.dump(attacked_logs, f, indent=4)
    
    print(f"{log_type.capitalize()} logs processed. {len(attacked_logs)} alerts generated.")

# Main function to initiate threads for each log type
def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    if not os.path.exists(PARSED_LOG_DIR):
        os.makedirs(PARSED_LOG_DIR)
    
    # Define and start threads for each log type
    threads = []
    for log_type in RULES_DIR.keys():
        thread = threading.Thread(target=process_logs, args=(log_type,))
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    print("Log processing complete.")

if __name__ == "__main__":
    main()
