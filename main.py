from api import Acunetix
import json_templace
import pyxl_templace

if __name__ == '__main__':
    api = Acunetix(username='hai@gmail.com', password='abcd.123', domain='127.0.0.1:3443')
    api.login()
    # target = api.create_target("http://testphp.vulnweb.com/", "tests2")
    # api.configure_target(target_id=target.get("target_id"), scan_speed="moderate")
    # scan_id = api.create_scan(target_id=target.get("target_id"), scan_type='11111111-1111-1111-1111-111111111111')
    scan_id = "3f3626a3-f6b1-4523-82a5-07a14748c8b5"
    scan = api.get_scan_url(scan_id)
    results_id = scan.get('current_session').get('scan_session_id')
    vulns = api.get_scan_vuln(scan_id, results_id)


    json_templace.write_json_file(vulns)

    #wirte data in xlxs file
    pyxl_templace.write_slsx(vulns)
