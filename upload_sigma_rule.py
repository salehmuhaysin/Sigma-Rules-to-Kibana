import requests
import json
import yaml
import csv
import argparse
import os
import fnmatch
import sigma

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


from sigma.conversion.base import Backend
from sigma.plugins import InstalledSigmaPlugins
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

plugins = InstalledSigmaPlugins.autodiscover()
backends = plugins.backends
pipeline_resolver = plugins.get_pipeline_resolver()
pipelines = list(pipeline_resolver.list_pipelines()) 

tactics = {
    "initial_access"        : {"id" : "TA0001", "name": "Initial Access" },
    "execution"             : {"id" : "TA0002", "name": "Execution" },
    "persistence"           : {"id" : "TA0003", "name": "Persistence" },
    "privilege_escalation"  : {"id" : "TA0004", "name": "Privilege Escalation" },
    "defense_evasion"       : {"id" : "TA0005", "name": "Defense Evasion" },
    "credential_access"     : {"id" : "TA0006", "name": "Credential Access" },
    "discovery"             : {"id" : "TA0007", "name": "Discovery" },
    "lateral_movement"      : {"id" : "TA0008", "name": "Lateral_Movement" },
    "collection"            : {"id" : "TA0009", "name": "Collection" },
    "exfiltration"          : {"id" : "TA0010", "name": "Exfiltration" },
    "command_and_control"   : {"id" : "TA0011", "name": "Command and Control" },
    "impact"                : {"id" : "TA0040", "name": "Impact" }
}
level_to_score = {
        "informational" : 10,
        "low" : 30,
        "medium" : 50,
        "high" : 75,
        "critical" : 100
    }
    
    
def convert_sigma_rule_to_lucene(sigma_rule):
    target = 'lucene'
    pipeline = ['ecs_windows']
    
    backend_class = backends[target]
    processing_pipeline = pipeline_resolver.resolve(pipeline)
    backend = backend_class(processing_pipeline=processing_pipeline)


    try:
        sigma_rule_collection = SigmaCollection.from_yaml(yaml.dump(sigma_rule))

        result = backend.convert(sigma_rule_collection)
        if isinstance(result, list):
            result = result[0]
    except SigmaError as e:
        return "Error: " + str(e)

    return result
    
def find_yaml_files(directory):
    yaml_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if fnmatch.fnmatch(file, '*.yaml') or fnmatch.fnmatch(file, '*.yml'):
                yaml_files.append(os.path.join(root, file))
    return yaml_files
    
    
def csv_to_json(file_path):
    data = {}
    with open(file_path, newline='') as csvfile:
        csvreader = csv.DictReader(csvfile)
        for row in csvreader:
            data[row['ID']] = row
    return data

def create_detection_rule(kibana_url, kibana_username, kibana_password, sigma_rule_dir, technique_file, group_file):
    technique = csv_to_json(technique_file)

    group = csv_to_json(group_file)
    sigma_rules = find_yaml_files(sigma_rule_dir)

    for sigma_rule_file in sigma_rules:
        try:
            with open(sigma_rule_file, 'r') as file:
                sigma_rule = yaml.safe_load(file)
        except: 
            print("Error: No valid yaml input")
            continue

        try:
            lucene_query = convert_sigma_rule_to_lucene(sigma_rule)
        except Exception as e:
            print(f"Failed converting sigma rule [{sigma_rule_file}]: {str(e)}")
            continue 
    
        try:
            name = sigma_rule['title']
            description = sigma_rule.get('description', '')
            severity = sigma_rule.get('level', 'low')
            tags = sigma_rule.get('tags', [])
            author = sigma_rule.get('author', [])
            if isinstance(author, str): author = author.split(",")
            references = sigma_rule.get('references', [])
            false_positives = sigma_rule.get('falsepositives', ['Unknown'])

            risk_score = level_to_score[severity]
            threat_tactics = {}
            for t in tags:
                if t.startswith("attack.") and t.split(".")[1] in tactics.keys():
                    threat_tactics[ tactics[t.split(".")[1]]['name'] ] = tactics[t.split(".")[1]]

            for t in tags:
                if t.startswith("attack.t"):
                    t_1 = t.split(".")[1].replace("t" , "T")
                    for t_1_t in technique[t_1]['tactics'].split(","):
                        t_1_t = t_1_t.strip(" ")
                        if t_1_t in threat_tactics.keys():
                            if 'techniques' not in threat_tactics[t_1_t].keys(): threat_tactics[t_1_t]['techniques'] = {}
                            threat_tactics[t_1_t]['techniques'][t_1] = technique[t_1]
                            threat_tactics[t_1_t]['techniques'][t_1]['subtechniques'] = {}

                            t_sub = t.split("." , 1)[1].replace("t" , "T")
                            if t_sub != t_1:
                                threat_tactics[t_1_t]['techniques'][t_1]['subtechniques'][t_sub] = technique[t_sub]


            threat = []
            for t in threat_tactics.keys():
                tactic = threat_tactics[t]
                techniques = []

                if 'techniques' in tactic.keys():
                    for tech in tactic['techniques'].keys():
                        subtechnique = []
                        if 'subtechniques' in tactic['techniques'][tech].keys():
                            for sub_t in tactic['techniques'][tech]['subtechniques'].keys():
                                subtechnique.append({
                                    'id' : tactic['techniques'][tech]['subtechniques'][sub_t]['ID'],
                                    'name' : tactic['techniques'][tech]['subtechniques'][sub_t]['name'],
                                    'reference' : tactic['techniques'][tech]['subtechniques'][sub_t]['url'],
                                })
                        techniques.append({
                            'id' : tactic['techniques'][tech]['ID'],
                            'name' : tactic['techniques'][tech]['name'],
                            'reference' : tactic['techniques'][tech]['url'],
                            'subtechnique' : subtechnique
                        })

                threat.append({
                    'framework' : "MITRE ATT&CK",
                    'tactic' : {
                        "id": tactic['id'],
                        "name": tactic['name'],
                        "reference": f"https://attack.mitre.org/tactics/{tactic['id']}"
                    },
                    'technique' : techniques
                })
            if severity == 'informational': severity = 'low'
            payload = {
                "type": "query",
                "language": "lucene",
                "query": lucene_query,
                "name": name,
                "description": description,
                "data_view_id":"logs-*",
                "interval": "5m",
                "from": "now-6m",
                "to": "now",
                "max_signals": 100,
                "severity" : severity,
                "risk_score" :risk_score,
                "author" :author,
                "references" :references,
                "false_positives" :false_positives,
                "tags" : [t for t in tags if not t.startswith('attack.t')],
                "threat" :threat
            }
            
            headers = {
                'kbn-xsrf': 'true',
                'Content-Type': 'application/json'
            }
            auth = (kibana_username, kibana_password)
            response = requests.post(f'{kibana_url}/api/detection_engine/rules', 
                                     headers=headers,
                                     auth=auth,
                                     data=json.dumps(payload),
                                     verify=False)  # Set verify to False to ignore SSL certificate verification

            if response.status_code == 200:
                print(f"Detection rule [{name}] created successfully!")
            else:
                print(f"Failed to create detection rule [{name}]. Status code:", response.status_code)
                print("Response:", response.json())
        except Exception as e:
            print(f"Failed pushing rule file [{sigma_rule_file}]: {str(e)}")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Push sigma rules to Kibana detection rules")

    parser.add_argument("--kibana_url", type=str, default='https://localhost:5601', help="URL of the Kibana instance")
    parser.add_argument("--kibana_username", type=str, default='elastic', help="Kibana username")
    parser.add_argument("--kibana_password", type=str, default='changeme', help="Kibana password")
    parser.add_argument("--sigma_rule_dir", type=str, default='./rules', help="Path to the Sigma rule files")
    parser.add_argument("--technique_file", type=str, default='./mitreattack.csv', help="Path to the MITRE ATT&CK CSV Technique file")
    parser.add_argument("--group_file", type=str, default='./miterattack-group.csv', help="Path to the MITRE ATT&CK CSV Group file")

    args = parser.parse_args()
    return args



if __name__ == "__main__":
    args = parse_arguments()
    create_detection_rule(args.kibana_url, args.kibana_username, args.kibana_password, args.sigma_rule_dir, args.technique_file , args.group_file)
    

