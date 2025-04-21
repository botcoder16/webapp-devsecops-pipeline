import json
import sys
import os
from collections import defaultdict

def parse_nuclei_results(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"Input file not found: {input_file}")
        sys.exit(1)

    grouped_alerts = {}

    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)

                title = data['info'].get('name', 'Unknown')
                severity = data['info'].get('severity', 'info')
                description = data['info'].get('description', '')
                reference = data.get('template-url', '')
                url = data.get('url')
                origin = data.get('host')
                parameter = data.get('fuzzing_parameter')
                curl_command = data.get('curl-command')
                http_request = data.get('request')

                if title not in grouped_alerts:
                    grouped_alerts[title] = {
                        'title': title,
                        'severity': severity,
                        'description': description,
                        'reference': reference,
                        'urls': [url] if url else [],
                        'origin': origin,
                        'parameter': parameter,
                        'curl_command': curl_command,
                        'http_request': http_request
                    }
                else:
                    alert = grouped_alerts[title]
                    if url and url not in alert['urls']:
                        alert['urls'].append(url)
                    if not alert['origin'] and origin:
                        alert['origin'] = origin
                    if not alert['parameter'] and parameter:
                        alert['parameter'] = parameter
                    if not alert['curl_command'] and curl_command:
                        alert['curl_command'] = curl_command
                    if not alert['http_request'] and http_request:
                        alert['http_request'] = http_request

            except json.JSONDecodeError as e:
                print(f"Skipping line due to JSON error: {e}")

    results = list(grouped_alerts.values())

    # Optional: organize under a fake category if you still want a nested dict
    structured_output = results  # flat list for combiner compatibility

    with open(output_file, 'w') as f:
        json.dump(structured_output, f, indent=2)
    print(f"\nParsed Nuclei results saved to: {output_file}")
    print(f"Total unique alerts: {len(results)}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python nuclei_parser.py input_file.json output_file.json")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]
    parse_nuclei_results(input_path, output_path)
