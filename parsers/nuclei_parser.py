import json
from datetime import datetime

def parse_nuclei_output(json_data):
    """
    Parse Nuclei JSON output and return structured results
    """
    results = []
    
    for entry in json_data.split('\n'):
        if not entry.strip():
            continue
            
        try:
            data = json.loads(entry)
            
            # Extract common fields
            result = {
                'template_id': data.get('template-id'),
                'template_name': data['info'].get('name'),
                'severity': data['info'].get('severity'),
                'author': data['info'].get('author', []),
                'tags': data['info'].get('tags', []),
                'host': data.get('host'),
                'matched_at': data.get('matched-at'),
                'timestamp': data.get('timestamp'),
                'matcher_name': data.get('matcher-name'),
                'description': data['info'].get('description', ''),
                'type': data.get('type'),
                'curl_command': data.get('curl-command', ''),
                'ip': data.get('ip')
            }
            
            # Add type-specific details
            if data.get('type') == 'dns':
                result.update({
                    'request': data.get('request'),
                    'response': data.get('response')
                })
            elif data.get('type') == 'http':
                result.update({
                    'url': data.get('url'),
                    'path': data.get('path'),
                    'port': data.get('port'),
                    'scheme': data.get('scheme'),
                    'request': data.get('request'),
                    'response': data.get('response'),
                    'status_code': data.get('response', '').split('\r\n')[0] if data.get('response') else ''
                })
            
            results.append(result)
            
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
            continue
            
    return results

def save_parsed_results(results, output_file):
    """
    Save parsed results to a JSON file
    """
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nParsed results saved to {output_file}")

def main():
    # Example usage with your provided JSON data
    input_file = '../scan_results/nuclei/nuclei_scan.json'
    output_file = '../combine/vulnerabilities_nuclei.json'
    
    with open(input_file, 'r') as f:
        json_data = f.read()
    
    results = parse_nuclei_output(json_data)
    save_parsed_results(results, output_file)

    # Print summary
    print(f"\nSummary:")
    print(f"Total findings: {len(results)}")
    print("Breakdown by type:")
    type_counts = {}
    for result in results:
        type_counts[result['type']] = type_counts.get(result['type'], 0) + 1
    for scan_type, count in type_counts.items():
        print(f"  {scan_type}: {count}")

if __name__ == '__main__':
    main()