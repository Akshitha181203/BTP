import sys
sys.path.append('../BTP/logparser/logparser/')
from Drain import LogParser
import threading
import re
import json
import os
import yaml
import networkx as nx
import matplotlib.pyplot as plt
import datetime
import pandas as pd

# Defining directories for logs and rules
RAW_LOG_DIR = './raw_logs'
PARSED_LOG_DIR = './parsed_logs'
RULES_DIR = {
    'network': './Network',
    'application': './Application',
    'system': './System'
}
OUTPUT_DIR = './output'

# Defining ordered stages and their y-axis positions
STAGES = [
    "Reconnaissance", "Initial Access", "Exploitation",
    "Installation/Persistence", "Command & Control",
    "Credential Access", "Lateral Movement",
    "Data Collection", "Exfiltration", "Impact"
]
stage_positions = {stage: idx for idx, stage in enumerate(STAGES)}

# Function to convert CSV to JSON
def convert_csv_to_json(csv_file_path, json_file_path):
    df = pd.read_csv(csv_file_path)
    df.to_json(json_file_path, orient="records", indent=4)
    print(f"Converted {csv_file_path} to {json_file_path}")

# Function to parse raw logs into a structured format using LogParser
def parse_logs_with_logparser(input_dir, output_dir, log_file, log_format, regex, st, depth):
    parser = LogParser(log_format, indir=input_dir, outdir=output_dir, depth=depth, st=st, rex=regex)
    parser.parse(log_file)

# Function to parse and save logs as JSON
def parse_logs(log_type):
    raw_log_file_path = os.path.join(RAW_LOG_DIR, f"{log_type}_logs.log")
    parsed_csv_file_path = os.path.join(PARSED_LOG_DIR, f"{log_type}_logs.log_structured.csv")
    parsed_json_file_path = os.path.join(PARSED_LOG_DIR, f"{log_type}_parsed.json")
    
    if os.path.exists(raw_log_file_path):
        print(f"Parsing {log_type} logs...")
        
        # Set LogParser parameters
        input_dir = RAW_LOG_DIR
        output_dir = PARSED_LOG_DIR
        log_file = f"{log_type}_logs.log"
        log_format = '<Date> <Time> <Pid> <Level> <Component>: <Content>'  # Customize as needed
        regex = [
            r'blk_(|-)[0-9]+',  # Block ID
            r'(/|)([0-9]+\.){3}[0-9]+(:[0-9]+|)(:|)',  # IP
            r'(?<=[^A-Za-z0-9])(\-?\+?\d+)(?=[^A-Za-z0-9])|[0-9]+$',  # Numbers
        ]
        st = 0.5  # Similarity threshold
        depth = 4  # Depth of all leaf nodes

        # Call LogParser
        parse_logs_with_logparser(input_dir, output_dir, log_file, log_format, regex, st, depth)

        # Convert CSV output to JSON
        if os.path.exists(parsed_csv_file_path):
            convert_csv_to_json(parsed_csv_file_path, parsed_json_file_path)
        else:
            print(f"Failed to parse logs for {log_type}")
    else:
        print(f"Raw log file for {log_type} not found at {raw_log_file_path}")
        return

# Function to load rules from a directory
def load_rules(rule_dir):
    rules = []
    for file in os.listdir(rule_dir):
        if file.endswith(".yml"):
            with open(os.path.join(rule_dir, file), 'r') as f:
                rules.append(yaml.safe_load(f))
    return rules

def apply_rules(logs, rules):
    attacked_logs = []  # Logs that match any rule
    threshold_trackers = {}  # Track thresholds for rules

    for log in logs:
        log_matched = False  # Tracks if the log satisfies any rule

        for rule in rules:
            # Initialize a tracker for the rule if not already present
            if rule["id"] not in threshold_trackers:
                threshold_trackers[rule["id"]] = {
                    "count": 0,
                    "size": 0,  # For data size thresholds
                    "start_time": None,  # Track the time window start
                    "matching_logs": []  # Store logs contributing to threshold
                }

            detection = rule.get("detection", {})
            basic_condition = detection.get("condition", "")
            thresholds = [key for key in detection if key.startswith("selection_")]

            # Track log matching based on conditions
            log_matched_for_rule = False

            # Check direct conditions first (e.g., IP, file name, event ID)
            if 'selection_ip' in detection:
                ip_conditions = detection['selection_ip']
                if log.get("source_ip") == ip_conditions.get("source_ip", "") or log.get("destination_ip") == ip_conditions.get("destination_ip", ""):
                    log["Alert"] = rule.get("description", "Condition Met Alert")
                    log["Stage"] = rule.get("stage", "Unknown")
                    log["Technique"] = rule.get("technique", "Unknown")
                    attacked_logs.append(log)
                    log_matched_for_rule = True

            if 'selection_file' in detection:
                file_conditions = detection['selection_file']
                if log.get("file_name") == file_conditions.get("file_name", ""):
                    log["Alert"] = rule.get("description", "Condition Met Alert")
                    log["Stage"] = rule.get("stage", "Unknown")
                    log["Technique"] = rule.get("technique", "Unknown")
                    attacked_logs.append(log)
                    log_matched_for_rule = True

            # If no direct match found, check for threshold-based conditions
            if not log_matched_for_rule:
                for threshold in thresholds:
                    selection = detection[threshold]
                    event_type_match = selection.get("event_type", "")
                    domain_match = selection.get("domain", "")
                    source_ip_match = selection.get("source_ip", "")
                    destination_ip_match = selection.get("destination_ip", "")
                    file_name_match = selection.get("file_name", "")
                    event_id_match = selection.get("event_id", "")
                    count = selection.get("condition", {}).get("count", 0)
                    size_threshold = selection.get("condition", {}).get("size", 0)  # For data size
                    time_window = selection.get("condition", {}).get("time_window", 0)

                    # Check if the log satisfies the basic matching conditions
                    if (
                        (not event_type_match or log.get("event_type") == event_type_match)
                        and (not domain_match or re.match(domain_match, log.get("domain", "")))
                        and (not source_ip_match or log.get("source_ip") == source_ip_match)
                        and (not destination_ip_match or log.get("destination_ip") == destination_ip_match)
                        and (not file_name_match or re.match(file_name_match, log.get("file_name", "")))
                        and (not event_id_match or log.get("event_id") == event_id_match)
                    ):
                        # If this log matches, add it to attacked_logs
                        log["Alert"] = rule.get("description", "Condition Met Alert")
                        log["Stage"] = rule.get("stage", "Unknown")
                        log["Technique"] = rule.get("technique", "Unknown")
                        attacked_logs.append(log)
                        log_matched_for_rule = True

                    # If threshold is present, track count and size
                    if log_matched_for_rule:
                        tracker = threshold_trackers[rule["id"]]
                        log_timestamp = datetime.datetime.fromisoformat(log["timestamp"])
                        log_size = log.get("data_size", log.get("packet_size", 0))  # Handle both data_size and packet_size

                        # Handle size threshold (no time limit)
                        if size_threshold > 0:
                            tracker["size"] += log_size
                            tracker["matching_logs"].append(log)

                            if tracker["size"] >= size_threshold:
                                # Add contributing logs to attacked_logs
                                for contributing_log in tracker["matching_logs"]:
                                    contributing_log["Alert"] = rule.get("description", "Data Size Threshold Alert")
                                    contributing_log["Stage"] = rule.get("stage", "Unknown")
                                    contributing_log["Technique"] = rule.get("technique", "Unknown")
                                    attacked_logs.append(contributing_log)

                                # Reset tracker after alert
                                tracker["size"] = 0
                                tracker["matching_logs"] = []

                        # Handle count threshold (with time window)
                        if count > 0 and time_window > 0:
                            # Initialize tracker start_time if not already set
                            if not tracker["start_time"]:
                                tracker["start_time"] = log_timestamp

                            # Check if the log falls within the time window
                            elapsed_time = (log_timestamp - tracker["start_time"]).total_seconds()
                            if elapsed_time <= time_window:
                                tracker["count"] += 1
                                tracker["matching_logs"].append(log)

                                if tracker["count"] >= count:
                                    # Add contributing logs to attacked_logs
                                    for contributing_log in tracker["matching_logs"]:
                                        contributing_log["Alert"] = rule.get("description", "Count Threshold Alert")
                                        contributing_log["Stage"] = rule.get("stage", "Unknown")
                                        contributing_log["Technique"] = rule.get("technique", "Unknown")
                                        attacked_logs.append(contributing_log)

                                    # Reset tracker after alert
                                    tracker["count"] = 0
                                    tracker["start_time"] = None
                                    tracker["matching_logs"] = []

                            else:
                                # Reset tracker if the time window expires
                                tracker["count"] = 1
                                tracker["start_time"] = log_timestamp
                                tracker["matching_logs"] = [log]

    return attacked_logs



# Function to process logs of a specific type
def process_logs(log_type, attacked_logs_all):
    parse_logs(log_type)
    rules = load_rules(RULES_DIR[log_type])
    parsed_log_file_path = os.path.join(PARSED_LOG_DIR, f"{log_type}_logs.json")
    
    if os.path.exists(parsed_log_file_path):
        with open(parsed_log_file_path, 'r') as f:
            logs = json.load(f)
        
        attacked_logs = apply_rules(logs, rules)
        
        output_file_path = os.path.join(OUTPUT_DIR, f"{log_type}_attacked_logs.json")
        with open(output_file_path, 'w') as f:
            json.dump(attacked_logs, f, indent=4)
        
        print(f"{log_type.capitalize()} logs processed. {len(attacked_logs)} alerts generated.")
        attacked_logs_all.extend(attacked_logs)  # Append to the shared list
    else:
        print(f"Parsed log file for {log_type} not found at {parsed_log_file_path}")
        return

# Function to create graph from attacked logs with stages
def create_stage_graph(attacked_logs):
    G = nx.DiGraph()
    
    x_offsets = {stage: 0 for stage in STAGES}  
    for i, log in enumerate(attacked_logs):
        stage = log.get("Stage", "Unknown")
        technique = log.get("Technique", "Unknown")
        pos_x = x_offsets[stage]
        pos_y = -stage_positions.get(stage, len(STAGES))
        G.add_node(i, label=f"{stage}\n{technique}", pos=(pos_x, pos_y))
        x_offsets[stage] += 1
    
    pos = {i: data["pos"] for i, data in G.nodes(data=True)}
    node_labels = {i: data["label"] for i, data in G.nodes(data=True)}
    node_colors = '#ff6666' 
    
    plt.figure(figsize=(10, 8))
    nx.draw(G, pos, labels=node_labels, node_color=node_colors, with_labels=True, node_size=1000, font_size=8)
    plt.title("Attack Lifecycle Graph by Stage")
    plt.xlabel("Logs within each stage")
    plt.ylabel("Attack Stages")
    plt.show()

# Main function for initiating threads for each log type
def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    if not os.path.exists(PARSED_LOG_DIR):
        os.makedirs(PARSED_LOG_DIR)
    
    # Defining and starting threads for each log type
    attacked_logs_all = []
    log_types = ['network', 'application', 'system']
    threads = []
    for log_type in log_types:
        thread = threading.Thread(target=process_logs, args=(log_type, attacked_logs_all))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    print("Log processing complete.")
    
    # Creating and displaying the graph
    create_stage_graph(attacked_logs_all)

if __name__ == "__main__":
    main()
