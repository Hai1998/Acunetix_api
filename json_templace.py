import json


class json_file:
    def write_json(self, data):
        # jsonData = json.dumps(data)
        # print(jsonData)
        with open('acunetic.json', 'w') as f:
            json.dump(data, f)


def write_json_file(vulns):
        data = []
        # write data in json file
        for vuln in vulns.get('vulnerabilities'):
            data.append(
                {'affects_url': vuln['affects_url'], 'severity': vuln['severity'], 'criticality': vuln['criticality'],
                 'affects_detail': vuln['affects_detail'], 'vt_name': vuln['vt_name'], 'last_seen': vuln['last_seen'],
                 'status': vuln['status']})
        json_file.write_json(data)
