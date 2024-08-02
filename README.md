# Sigma-Rules-to-Kibana


## Upload Sigma Rule Script

This script facilitates the uploading of Sigma rules to Kibana detection rules.

### Deployment

To install the required dependencies, run the following command:

```sh
pip3 install -r requirements.txt
```

### Usage

```sh
python3 upload_sigma_rule.py [-h] [--kibana_url KIBANA_URL] [--kibana_username KIBANA_USERNAME] [--kibana_password KIBANA_PASSWORD] [--sigma_rule_dir SIGMA_RULE_DIR] [--technique_file TECHNIQUE_FILE] [--group_file GROUP_FILE]
```

#### Example:
```sh
python3 upload_sigma_rule.py --kibana_url https://localhost:5601 --kibana_username elastic --kibana_password changeme --sigma_rule_dir ./sigma/rules --technique_file ./mitreattack.csv  --group_file mitreattack-group.csv
```

### Options
```
- `-h, --help`: Show the help message and exit.
- `--kibana_url KIBANA_URL`: URL of the Kibana instance.
- `--kibana_username KIBANA_USERNAME`: Kibana username.
- `--kibana_password KIBANA_PASSWORD`: Kibana password.
- `--sigma_rule_dir SIGMA_RULE_DIR`: Path to the Sigma rule files.
- `--technique_file TECHNIQUE_FILE`: Path to the MITRE ATT&CK CSV Technique file.
- `--group_file GROUP_FILE`: Path to the MITRE ATT&CK CSV Group file.
```


## License

This project is licensed under the MIT License - see the LICENSE.md file for details.
