import threading
import re
import json
import os
import yaml
import networkx as nx
import matplotlib.pyplot as plt
import datetime

# Define directories for logs and rules
RAW_LOG_DIR = './raw_logs'
PARSED_LOG_DIR = './parsed_logs'
RULES_DIR = {
    'network': '/Network/rules',
    'application': '/Application/rules',
    'system': '/System/rules'
}
OUTPUT_DIR = './output'

# Define ordered stages and their y-axis positions
STAGES = [
    "Reconnaissance", "Initial Access", "Exploitation",
    "Installation/Persistence", "Command & Control",
    "Credential Access", "Lateral Movement",
    "Data Collection", "Exfiltration", "Impact"
]
stage_positions = {stage: idx for idx, stage in enumerate(STAGES)}

# Function to parse raw logs into a structured format
def parse_logs_with_logparser(line, log_type):
    # Placeholder parsing logic
    return None

# Function to parse and save parsed logs
def parse_logs(log_type):
    parsed_logs = parse_logs_with_logparser(log_type)
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
        if file.endswith(".yml"):
            with open(os.path.join(rule_dir, file), 'r') as f:
                rules.append(yaml.safe_load(f))
    return rules

def apply_rules(logs, rules):
    attacked_logs = [] 
    threshold_trackers = {}  # Track thresholds for rules

    for log in logs:
        log_matched = False  
        
        for rule in rules:
            if rule["id"] not in threshold_trackers:
                threshold_trackers[rule["id"]] = {
                    "count": 0,
                    "size": 0,  
                    "start_time": None,  
                    "matching_logs": [] 
                }

            detection = rule.get("detection", {})
            basic_condition = detection.get("condition", "")
            thresholds = [key for key in detection if key.startswith("selection_")]

            if thresholds:
                for threshold in thresholds:
                    selection = detection[threshold]
                    event_type_match = selection.get("event_type", "")
                    domain_match = selection.get("domain", "")
                    count = selection.get("condition", {}).get("count", 0)
                    size_threshold = selection.get("condition", {}).get("size", 0)  
                    time_window = selection.get("condition", {}).get("time_window", 0)

                    # Check if the log satisfies the basic matching conditions
                    if (
                        (not event_type_match or log.get("event_type") == event_type_match)
                        and (not domain_match or re.match(domain_match, log.get("domain", "")))
                    ):
                        log_matched = True
                        tracker = threshold_trackers[rule["id"]]
                        log_timestamp = datetime.datetime.fromisoformat(log["timestamp"])
                        log_size = log.get("data_size", log.get("packet_size", 0))  

                        if size_threshold > 0:
                            tracker["size"] += log_size
                            tracker["matching_logs"].append(log)

                            if tracker["size"] >= size_threshold:
                                for contributing_log in tracker["matching_logs"]:
                                    contributing_log["Alert"] = rule.get("description", "Data Size Threshold Alert")
                                    contributing_log["Stage"] = rule.get("stage", "Unknown")
                                    contributing_log["Technique"] = rule.get("technique", "Unknown")
                                    attacked_logs.append(contributing_log)

                                tracker["size"] = 0
                                tracker["matching_logs"] = []

                        if count > 0 and time_window > 0:
                            if not tracker["start_time"]:
                                tracker["start_time"] = log_timestamp

                            elapsed_time = (log_timestamp - tracker["start_time"]).total_seconds()
                            if elapsed_time <= time_window:
                                tracker["count"] += 1
                                tracker["matching_logs"].append(log)

                                if tracker["count"] >= count:
                                    for contributing_log in tracker["matching_logs"]:
                                        contributing_log["Alert"] = rule.get("description", "Count Threshold Alert")
                                        contributing_log["Stage"] = rule.get("stage", "Unknown")
                                        contributing_log["Technique"] = rule.get("technique", "Unknown")
                                        attacked_logs.append(contributing_log)

                                    tracker["count"] = 0
                                    tracker["start_time"] = None
                                    tracker["matching_logs"] = []

                            else:
                                tracker["count"] = 1
                                tracker["start_time"] = log_timestamp
                                tracker["matching_logs"] = [log]
            elif basic_condition:
                if re.search(basic_condition, log["message"]):
                    log_matched = True
                    log["Alert"] = rule.get("description", "Rule Matched")
                    log["Stage"] = rule.get("stage", "Unknown")
                    log["Technique"] = rule.get("technique", "Unknown")
                    attacked_logs.append(log)
    return attacked_logs


# Function to process logs of a specific type
def process_logs(log_type):
    parse_logs(log_type)
    rules = load_rules(RULES_DIR[log_type])
    parsed_log_file_path = os.path.join(PARSED_LOG_DIR, f"{log_type}_logs.json")
    with open(parsed_log_file_path, 'r') as f:
        logs = json.load(f)
    
    attacked_logs = apply_rules(logs, rules, log_type)
    
    output_file_path = os.path.join(OUTPUT_DIR, f"{log_type}_attacked_logs.json")
    with open(output_file_path, 'w') as f:
        json.dump(attacked_logs, f, indent=4)
    
    print(f"{log_type.capitalize()} logs processed. {len(attacked_logs)} alerts generated.")
    return attacked_logs

# Function to create a graph from attacked logs with stages as in the provided image
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

# Main function to initiate threads for each log type
def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    if not os.path.exists(PARSED_LOG_DIR):
        os.makedirs(PARSED_LOG_DIR)
    
    # Define and start threads for each log type
    threads = []
    attacked_logs_all = []
    for log_type in RULES_DIR.keys():
        thread = threading.Thread(target=lambda: attacked_logs_all.extend(process_logs(log_type)))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    print("Log processing complete.")
    
    # Create and display the graph
    create_stage_graph(attacked_logs_all)

if __name__ == "__main__":
    main()
