import hashlib
import requests
import json
import requests
import argparse
import logging
import urllib3


class AuthenticationError(Exception):
    pass


class Acunetix(requests.Session):
    REPORT_TEMPLATES = {}
    SCANNING_PROFILES = {}

    def __init__(self, username=None, password=None, domain=None, ssl_verify=False):
        # if any([not username, not password, not domain]):
        # raise ValueError("username, password and domain are required")
        requests.packages.urllib3.disable_warnings()
        super(Acunetix, self).__init__()

        self.verify = ssl_verify

        self.timeout = 2

        self.headers = {
            "Accept": "application / json, text / plain, * / *",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21",
            "Content-Type": "application/json;charset=UTF-8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
        }
        url = ["https://", domain]
        self.authenticated = False
        self.max_redirects = 0
        self.username = username
        self.password = hashlib.sha256(password.encode("utf-8")).hexdigest()
        self.url = "".join(url)
        self.check_connectivity()

    def request(self, *args, **kwargs):
        try:
            return super(Acunetix, self).request(timeout=1, *args, **kwargs)
        except Exception as e:
            print("[!] Error : {}".format(e.__repr__()))
            return False

    def login(self):
        """
        This should be the first call on initialized Acunetix object
        :return: Server info like license, expiry etc
        """
        url = self.url + "/api/v1/me/login"
        data = {"email": self.username, "password": self.password, "remember_me": False}
        resp = self.post(url, json=data)
        if resp.status_code == 204 and "X-Auth" in resp.headers:
            self.authenticated = True
            self.headers.update({"X-Auth": resp.headers['X-Auth']})
            return self.me
        else:
            raise AuthenticationError("Failed to authenticate")

    def logout(self):
        """
        logout whenever required
        :return: Boolean
        """
        url = self.url + "/api/v1/me/logout"
        resp = self.post(url, json={})
        if resp.status_code == 204:
            self.authenticated = False
        return self.authenticated

    def check_connectivity(self):
        """
        Checks server connectivity by making a call to http://server/build.json
        :return: build number of Acunetix app running on server
        """
        try:
            url = self.url + "/build.json"
            resp = self.get(url)
            self.build = resp.json()['build']
            return self.build
        except Exception as e:
            return False

    @property
    def stats(self):
        """
        Gets server stats
        :return: JSON response from server
        """
        url = self.url + "/api/v1/me/stats"
        return self.get(url).json()

    @property
    def info(self):
        """
        Get server info
        :return: JSON response from server
        """
        url = self.url + "/api/v1/info"
        return self.get(url).json()

    @property
    def me(self):
        """
        Get server license info, expiry etc
        :return: JSON response from server
        """
        url = self.url + "/api/v1/me"
        return self.get(url).json()

    @property
    def license(self):
        """
        Calls self.info and return license info
        :return: License info from server
        """
        return self.info['license']

    @property
    def notifications(self):
        """
        TODO
        :return: Notifications
        """
        url = self.url + "/api/v1/notifications/count"
        if self.get(url).json()['count'] > 0:
            url = self.url + "/api/v1/notifications"
            return self.get(url).json()['notifications']
        return None

    @property
    def scanning_profiles(self):
        """
        Get scanning profiles (scan types configurations)
        :return: Scanning profiles with their ID
        """
        url = self.url + "/api/v1/scanning_profiles"
        profiles = self.get(url).json()["scanning_profiles"]
        for profile in profiles:
            self.SCANNING_PROFILES.update({profile["profile_id"]: profile["name"]})
        return self.SCANNING_PROFILES

    @property
    def targets(self):
        """
        TODO: Cursor implementation
        Gets targets info from server
        :return: JSON Array (list) from server response
        """
        url = self.url + "/api/v1/targets?l={}".format(100)
        return self.get(url).json()['targets']

    def target(self, target_id, configuration=False):
        """
        Gets target info for supplied target_id from server
        :param target_id: str(target_id)
        :param configuration: boolean (whether to return target configuration information too)
        :return: JSON response from server
        """
        url = self.url + "/api/v1/targets/{}".format(target_id)
        target = self.get(url).json()
        if configuration:
            url = self.url + "/api/v1/targets/{}/configuration".format(target_id)
            target.update({"configuration": self.get(url).json()})
        return target

    def delete_target(self, target_id):
        """
        Deletes a target from server
        :param target_id: str(target_id)
        :return: boolean (True = Success)
        """
        url = self.url + "/api/v1/targets/{}".format(target_id)
        if self.delete(url).status_code == 204:
            return True
        return False

    def create_target(self, address, description):
        """
        Create a new target on server
        :param address: Must be a fq URL address (eq: http://test.com)
        :param description: Some description about the target
        :return: JSON response from server
        """
        url = self.url + "/api/v1/targets"
        data = {"address": str(address), "description": str(description)}
        resp = self.post(url, json=data)
        if resp.status_code == 201:
            return resp.json()
        return False

    def configure_target(self, target_id, scan_speed=None, site_login=False,
                         authentication=None, technologies=None, custom_headers=None, custom_cookies=None):
        """
        Configure a target object with the below options
        :param target_id: Server return valid target_id
        :param scan_speed: Must be one of these ("sequential", "slow", "moderate", "fast")
        :param site_login: Must be a list in this format ["type", "username", "password"]
                            For now type will be automatic only
        :param authentication: Must be a list in this format ["username", "password"]
        :param technologies: Must be a list containing technologies from the follow (ex: ["Python", "Perl"])
                            Supported technologies are ("ASP","ColdFusion/Jrun","ASP.NET","Python","PHP","Rails","Perl","FrontPage","Java/J2EE","Node.js")
        :param custom_headers: Must be a list in this format ["Header: Value"]
        :param custom_cookies: Must be a list in this format [["url", "cookieValue"]]
        :return: Server returned configuration
        """
        url = self.url + "/api/v1/targets/{}/configuration".format(target_id)
        data = {}

        if scan_speed and scan_speed in ["sequential", "slow", "moderate", "fast"]:
            data.update({"scan_speed": scan_speed})
        else:
            data.update({"scan_speed": "fast"})

        if site_login and isinstance(site_login, list):
            if len(site_login) == 3:
                data.update({"login": {"kind": "automatic", "credentials": {"enabled": True, "username": site_login[1],
                                                                            "password": site_login[2]}}})
        else:
            data.update({"login": {"kind": "none"}})

        if authentication and isinstance(authentication, list):
            if len(authentication) == 2:
                data.update(
                    {"authentication": {"enabled": True, "username": authentication[0], "password": authentication[1]}})
        else:
            data.update({"authentication": {"enabled": False}})

        if technologies and isinstance(technologies, list):
            data.update({"technologies": technologies})
        else:
            data.update({"technologies": []})

        if custom_headers and isinstance(custom_headers, list):
            data.update({"custom_headers": custom_headers})
        else:
            data.update({"custom_headers": []})

        if custom_cookies and isinstance(custom_cookies, list):
            data.update({"custom_cookies": [{"url": i[0], "cookie": i[1]} for i in custom_cookies]})
        else:
            data.update({"custom_cookies": []})

        resp = self.patch(url, json=data)
        if resp.status_code == 204:
            return self.get(url).json()

    @property
    def scans(self):
        url = self.url + "/api/v1/scans"
        resp = self.get(url)
        return resp

    def stop_scan(self, scan_id):
        """
        Abort a scan
        :param scan_id: str(scan_id)
        :return: response status_code
        """
        url = self.url + "/api/v1/scans/{}/abort".format(str(scan_id))
        resp = self.post(url, json={})
        return resp.status_code

    def create_scan(self, target_id, scan_type, report_templated_id=None):
        """
        Create a new scan on server
        :param target_id: str(target_id)
        :param scan_type: str(scan_type_id) can be from the following
                ('11111111-1111-1111-1111-111111111111', 'Full Scan'),
                ('11111111-1111-1111-1111-111111111112', 'High Risk Vulnerabilities'),
                ('11111111-1111-1111-1111-111111111116', 'Cross-site Scripting Vulnerabilities'),
                ('11111111-1111-1111-1111-111111111113', 'SQL Injection Vulnerabilities'),
                ('11111111-1111-1111-1111-111111111115', 'Weak Passwords'),
                ('11111111-1111-1111-1111-111111111117', 'Crawl Only'),
        :param report_templated_id: Optional, scan be from the following
                ('11111111-1111-1111-1111-111111111111', 'Developer'),
                ('11111111-1111-1111-1111-111111111112', 'Quick'),
                ('11111111-1111-1111-1111-111111111113', 'Executive Summary'),
                ('11111111-1111-1111-1111-111111111115', 'Affected Items'),
                ('11111111-1111-1111-1111-111111111124', 'Scan Comparison'),
                ('11111111-1111-1111-1111-111111111119', 'OWASP Top 10 2013'),
                ('11111111-1111-1111-1111-111111111125', 'OWASP Top 10 2017'),
        :return: scan_id of newly created scan
        """
        url = self.url + "/api/v1/scans"
        data = {
            "target_id": target_id,
            "profile_id": scan_type,
            "schedule": {
                "disable": False,
                "start_date": None,
                "time_sensitive": False
            }

        }

        if report_templated_id:
            data.update({"report_template_id": report_templated_id})

        resp = self.post(url, json=data)
        scan_id = resp.headers['Location'].split('/')[-1]
        return scan_id

    def delete_scan(self, scan_id):
        """
        TODO: verify that the scan is stopped
        Abort a scan and then delete it from server
        :param scan_id: str(scan_id)
        :return:
        """
        self.stop_scan(scan_id)
        url = self.url + "/api/v1/scans/{}".format(str(scan_id))
        resp = self.delete(url)
        return resp.status_code

    def scan_status(self, scan_id, extra_stats=False):
        """
        Makes 2 calls to server in order a create a stat dict
        :param scan_id: str(scan_id)
        :param extra_stats: boolean (True fetches all stats, False fetches basic)
        :return:  dict(stats)
        """
        url = self.url + "/api/v1/scans/{}".format(str(scan_id))
        resp = self.get(url).json()

        if 'code' in resp and resp['code'] == 404:  # if scan doesn't exists on server
            return None

        progress = resp['current_session']['progress']
        status = resp['current_session']['status']
        vuln_stats = None
        if status != "scheduled":
            vuln_stats = resp['current_session']['severity_counts']
            vuln_stats["informational"] = vuln_stats.pop("info")

        data = {'progress': progress, 'status': status, 'vuln_stats': vuln_stats,
                'session_id': resp['current_session']['scan_session_id']}

        if extra_stats:
            url = url + '/results/{}/statistics'.format(resp['current_session']['scan_session_id'])
            resp = self.get(url).json()
            aborted = resp['scanning_app']['wvs']['abort_requested']
            start_date = resp['scanning_app']['wvs']['start_date']
            end_data = resp['scanning_app']['wvs']['end_date']
            data.update({'aborted': aborted, 'start_date': start_date, 'end_date': end_data})

        return data

    def get_scan_vulnerabilities(self, scan_id):
        """
        TODO: cursor implementation (pagination)
        Gets all vulnerabilities related to supplied scan_id
        :param scan_id: str(scan_id)
        :return: JSON response from server
        """
        url = self.url + "/api/v1/scans/{}".format(str(scan_id))
        resp = self.get(url).json()
        url = url + '/results/{}/vulnerabilities'.format(resp['current_session']['scan_session_id'])
        resp = self.get(url).json()['vulnerabilities']
        return resp

    def get_target_vulnerabilities(self, target_id):
        """
        Gets all vulnerabilities related to supplied target_id by first getting last associated scan_id
        :param target_id: str(target_id)
        :return: result or None
        """
        scan_id = self.target(target_id)['last_scan_session_id']
        if scan_id:
            return self.get_scan_vulnerabilities(scan_id)
        else:
            return None

    def get_vulnerability_by_id(self, scan_id, vulnerability_id, scan_session_id=None):
        """
        Get single vulnerability details
        :param vulnerability_id: Vulnerability ID
        :param scan_session_id: (optional)
        :return: JSON response from server
        """
        if not scan_session_id:
            scan_session_id = self.scan_status(scan_id)['session_id']
        url = self.url + "/api/v1/scans/{}/results/{}/vulnerabilities/{}".format(scan_id, scan_session_id,
                                                                                 vulnerability_id)
        resp = self.get(url).json()
        return resp

    @property
    def report_templates(self):
        """
        Gets report templates from server
        :return: dict(Template ID and Info)
        """
        url = self.url + "/api/v1/report_templates"
        resp = self.get(url)
        templates = resp.json()['templates']
        for i in templates:
            self.REPORT_TEMPLATES.update({i['template_id']: {"name": i["name"], "group": i['group']}})
        return self.REPORT_TEMPLATES

    scan_vulnerability_report = dict()
    logging.basicConfig(level=logging.ERROR)
    CONTENT_TYPE = "application/json"
    ACUNETIX_API_URI = "/api/v1"
    scan_vulnerability_report = dict()
    urllib3.disable_warnings()

    def get_acunetix_request_headers(self, api_auth_token):
        acunetix_headers = dict()
        acunetix_headers['X-Auth'] = api_auth_token
        acunetix_headers['Content-type'] = self.CONTENT_TYPE
        return acunetix_headers

    def get_scan_url(self, scan_id):
        url = self.url + "/api/v1/scans/{}".format(scan_id)
        resp = self.get(url).json()
        return resp

    def get_scan_vulnerabilities_url(self, scan_url, scan_session_id):
        url = self.url + "/api/v1/{}/results/{}/vulnerabilities".format(scan_url, scan_session_id)
        resp = self.get(url).json()
        return resp

    def get_scan_vulnerabilities_id(self, scan_id):
        url = self.url + "/api/v1/scans/{}".format(scan_id)
        resp = self.get(url)
        if resp.status_code:
            return resp.json()
        return None

    def get_request_headers(self, api_auth_token):
        """
            This method returns request headers required by 'requests' api.
        :param api_auth_token:
        :return: headers
        """
        headers = requests.utils.default_headers()
        acunetix_headers = self.get_acunetix_request_headers(api_auth_token)
        headers.update(acunetix_headers)
        return headers

    def get_json_response(self, url, disable_ssl_warnings, api_auth_token=None):
        headers = self.get_request_headers(api_auth_token)
        try:
            response = None

            if disable_ssl_warnings:
                response = requests.get(self.url, headers=headers, verify=False)
            else:
                response = requests.get(self.url, headers=headers)

            response.raise_for_status()
            decode_response = response.content.decode('utf-8')
            json_response = json.loads(decode_response)
            return json_response
        except requests.exceptions.HTTPError as he:
            logging.error("Error: {he}".format(he=he))
            raise he
        except requests.exceptions.ConnectionError as ce:
            logging.error("Error: {ce}".format(ce=ce))
            raise ce
        except requests.exceptions.Timeout as t:
            logging.error("Error: {t}".format(t=t))
            raise t
        except requests.exceptions.RequestException as re:
            logging.error("Error: Fetching response from the {url} .".format(url=url))
            raise re

    def get_scan_vulnerabilities_json_response(self, url, disable_ssl_warnings):
        cursor = 0
        vulnerabilities_details = []
        scan_vulnerabilities_json_response = dict()

        while True:
            cursor_url = url + "?c=" + str(cursor)
            json_response = self.get_json_response(cursor_url, disable_ssl_warnings)
            [vulnerabilities_details.append(vulnerability) for vulnerability in json_response['vulnerabilities']]
            cursor = json_response['pagination']['next_cursor']
            if not cursor:
                break

        scan_vulnerabilities_json_response['vulnerabilities'] = vulnerabilities_details
        return scan_vulnerabilities_json_response

    # def get_scan_session_id(self):
    #     return self.json_response['current_session']['scan_session_id']
    #
    # # def get_scan_vulnerabilities_url(self, scan_session_id):
    #     url = self.url + "/api/v1/scans/results/{}/vulnerabilities".format(scan_session_id)
    #     return self.get(url).json()

    def get_scan_vulnerabilities_ids(self):
        scan_vulnerabilities_ids = [i['vuln_id'] for i in self.scan_vulnerabilities_json_response['vulnerabilities']]
        return scan_vulnerabilities_ids

    def get_vulnerabilities_url(self, scan_session_id, vulnerabilities_id):
        url = self.url + "/api/v1/scans/results/{}/vulnerabilities/{}".format(scan_session_id, vulnerabilities_id)
        return self.get(url).json()

    def get_vulnerabilities_details(self, api_auth_token, scan_vulnerabilities_ids, disable_ssl_warnings):
        vulnerability_details = []
        for vulnerability_id in scan_vulnerabilities_ids:
            vulnerability_url = self.get_vulnerabilities_url(vulnerability_id)
            json_response = self.get_json_response(vulnerability_url, api_auth_token, disable_ssl_warnings)
            vulnerability_details.append(json_response)
        return vulnerability_details

    def get_scan_vulnerabilities_json_report(self, json_response, vulnerabilities_details):
        scan_vulnerability_details = dict()
        scan_vulnerability_details['scan_id'] = json_response['scan_id']
        scan_vulnerability_details['scan_criticality'] = json_response['criticality']
        scan_vulnerability_details['scan_start_date'] = json_response['current_session']['start_date']
        scan_vulnerability_details['scan_profile_name'] = json_response['profile_name']
        scan_vulnerability_details['scan_target_address'] = json_response['target']['address']
        scan_vulnerability_details['scan_target_id'] = json_response['target_id']
        scan_vulnerability_details['issues'] = vulnerabilities_details
        scan_vulnerabilities_json_report = json.dumps(scan_vulnerability_details)
        return scan_vulnerabilities_json_report

    def get_scan_vuln(self, scan, results):
        url = self.url + "/api/v1/scans/{}/results/{}/vulnerabilities".format(scan, results)
        resp = self.get(url)
        if not resp or resp.status_code != 200:
            print("request err {}".format(str(resp.json())))
            return {}
        return resp.json()
