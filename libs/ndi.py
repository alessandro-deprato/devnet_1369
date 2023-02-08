#!/usr/bin/env python3

import json
import logging
import requests
import pyrfc3339
from datetime import datetime, timezone, timedelta
from xml.etree import ElementTree as ET
from requests.packages.urllib3.exceptions import InsecureRequestWarning

LOG = logging.getLogger("devnet")

class Ndi(object):
    """
    Master Class for NDI API
    """

    def __init__(self, address, credentials=None, api_key=None, insight_group=None):
        """
        :param address: IP address or FQDN
        :param credentials: {'userName': '', 'userPasswd': '', 'domain': 'DefaultAuth'}
        :param api_key: ND API Key
        :param insight_group: ND insight group. Better defining it here if you plan to work only with a specific site
        """
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        LOG.info("A new NDI Instance is being started")
        # Attribute initialization
        self._address = address
        self._url = "https://%s/sedgeapi/v1/cisco-nir/api/api" % address
        self._token = None
        self._credentials = credentials
        if not insight_group:
            self.insight_group = ""
        else:
            self.insight_group = insight_group
        if api_key:
            # API KEY TAKES PRECEDENCE
            LOG.info("Setting API Key")
            self.token = {"X-Nd-Apikey": api_key["api_key"], "X-Nd-Username": api_key["username"]}
            self.cookie = None
        elif credentials:
            # credentials = {'userName': 'XXX', 'userPasswd': 'XXX', 'domain': 'DefaultAuth'}
            LOG.info("Attempting NDI Auth with credentials")
            self.token = None
            self.get_nd_token(self.credentials)

    def __str__():
        return "This is an NDI object"

    @property
    def address(self):
        """Get credentials"""
        return self._address

    @address.setter
    def address(self, value):
        """Set the credentials"""
        self._address = value

    @property
    def credentials(self):
        """Get credentials"""
        return self._credentials

    @credentials.setter
    def credentials(self, value):
        """Set the credentials"""
        self._credentials = value

    @property
    def cookie(self):
        """Get cookie"""
        return self._cookie

    @cookie.setter
    def cookie(self, value):
        """Set the cookie"""
        self._cookie = value

    @property
    def token(self):
        """Get token"""
        return self._token

    @token.setter
    def token(self, value):
        """Set the token"""
        self._token = value

    @property
    def url(self):
        """Get url"""
        return self._url

    @url.setter
    def url(self, value):
        """Set the url"""
        self._url = value

    @property
    def insight_group(self):
        """Get insight_group"""
        return self._insight_group

    @insight_group.setter
    def insight_group(self, value):
        """Set the insight_group"""
        self._insight_group = value

    def get_nd_token(self, credentials):
        """
        To be used in case you want to authenticate with user credentials. Token received will be
        used as cookie. No Cookie refresh yet.
        TODO: Add Cookie refresh feature
        :param credentials:
        :return:  Bool()
        """
        auth_url = "https://%s/login" % self.address
        LOG.debug(f"Running Auth query at {auth_url}")
        auth_result = requests.post(auth_url, json=credentials, verify=False)

        if auth_result.status_code == 200:
            self.cookie = {"AuthCookie": auth_result.json()["jwttoken"]}
            LOG.info(f"Authentication succeded")
        else:
            LOG.error(f"Authentication failed, {auth_result.status_code}, {auth_result.text}")
            return  False
        return True

    def normalize_insight_group_uri(self, url, insight_group):
        """
        We check if insight group is required for this API call and if it was specified either during object init
        or via method parameter
        :param url: str with API URL
        :param insight_group: str with IG name
        :return: URL
        """
        if not insight_group:
            LOG.error("Looks like insight group is not set. Set it globally in the class or in the specific call")
        if "{ig_name}" in url:
            url = url.replace("{ig_name}", insight_group)
            return url
        else:
            return url

    def generic_get(self, uri_object, ig_name=""):
        """
        Get any data
        """
        url = self.normalize_insight_group_uri("%s/%s" % (
            self.url, uri_object), self.insight_group or ig_name)
        LOG.debug(f"GET URL:{url}")
        result = requests.get(url, verify=False, cookies=self.cookie, headers=self.token)
        if 199 < result.status_code < 300:
            LOG.debug(f"GET to {url} completed")
            return True, result.json()
        else:
            LOG.error(f"GET failed, {result.status_code}, {result.text}")
            return False, ""

    def generic_post(self, uri_object, payload=None, ig_name="", files=None):
        """
        Get any data
        """
        url = self.normalize_insight_group_uri("%s/%s" % (
            self.url, uri_object), self.insight_group or ig_name)
        LOG.debug(f"POST URL:{url}")
        result = requests.post(url, verify=False, cookies=self.cookie, headers=self.token, json=payload, files=files)
        if 199 < result.status_code < 300:
            LOG.debug(f"POST to {url} completed")
            return True, result.json()
        else:
            LOG.error(f"POST failed, {result.status_code}, {result.text}")
            return False, ""

    def generic_delete(self, uri_object, ig_name="", files=None):
        """
        :param uri_object:
        :param ig_name:
        :param files:
        :return:
        """

        url = self.normalize_insight_group_uri("%s/%s" % (
            self.url, uri_object), self.insight_group or ig_name)
        LOG.debug(f"DELETE URL:{url}")
        result = requests.delete(url, verify=False, cookies=self.cookie, headers=self.token)
        if 199 < result.status_code < 300:
            LOG.debug(f"DELETE to {url} completed")
            return True, result.json()
        else:
            LOG.error(f"DELETE failed, {result.status_code}, {result.text}")
            return False, ""

    def get_site_uuid_by_name(self, site_name):
        """
        """

        uri = "telemetry/v2/config/insightsGroup/{ig_name}/fabric/%s" % site_name
        result, data = self.generic_get(uri)
        if not result:
            return False
        else:
            return data["value"]["data"]["uuid"]

    def get_all_pcv_jobs(self, ig_name=None):
        """
        """
        uri = "/telemetry/v2/config/insightsGroup/{ig_name}/prechangeAnalysis"
        result, data = self.generic_get(uri)
        if not result:
            return False
        else:
            return data

    def get_pcv_by_id(self, pcv_id, site_name, ig_name=None):
        """
        """
        uri = "telemetry/v2/config/insightsGroup/{ig_name}/fabric/%s/prechangeAnalysis/%s" % (site_name, pcv_id)
        result, data = self.generic_get(uri)
        if not result:
            return False
        else:
            return data

    def query_assurance_analysis(self,site_name, ig_name=None):
        """
        :param site_name:
        :param ig_name:
        :return:
        """
        uri = "telemetry/v2/jobs/summary.json?insightsGroupName={ig_name}"
        result, data = self.generic_get(uri)
        if not result:
            return False
        else:
            return data


    def stop_assurance_analysis(self,site_name, ig_name=None):
        """
        :param site_name:
        :param ig_name:
        :return:
        """
        all_jobs = self.query_assurance_analysis(site_name)
        for job in all_jobs["entries"]:
            if (job["operSt"]) in ["RUNNING"]:
                data = {"instanceId":job["jobId"]}
                uri = "telemetry/v2/insightsGroup/dc_spain/fabric/MLG01/jobs/stop.json"
                self.generic_post(uri, data)


    def get_pcv_status(self, pcv_id, site_name, ig_name=None):
        """
        """
        uri = "telemetry/v2/config/insightsGroup/{ig_name}/prechangeAnalysis?" \
              "$sort=-analysisSubmissionTime&$page=0&$size=10&fabricId=%s" % (self.get_site_uuid_by_name(site_name))
        result, data = self.generic_get(uri)
        if not result:
            return False
        else:
            for pcv in data["value"]["data"]:
                if pcv["jobId"] == pcv_id:
                    return pcv


    def new_pcv_job(self, site_name, file_content, ig_name=None, epoch_id=None):
        """
        :param site_name:
        :param file_content:
        :param ig_name:
        :param epoch_id:
        :return:
        """
        # First of all we validate the file and so we detect the mimetype
        # mimetypes.guess_type is not reliable

        mime = None
        try:
            json.loads(file_content)
            mime = ('application/json', None)
            LOG.debug("PCV file is a valid JSON")
            file_name = datetime.now().strftime("%Y%m%d_%H_%M_%S_API_PCV.json")
        except json.decoder.JSONDecodeError:
            pass
        try:
            ET.fromstring(file_content)
            mime = ('application/xml', None)
            LOG.debug("PCV file is a valid XML")
            file_name = datetime.now().strftime("%Y%m%d_%H_%M_%S_API_PCV.json")
        except ET.ParseError:
            pass
        if not mime:
            LOG.error("Unable to detect PCV File format, only valid JSON and XML are supported")
            return False
        uri = "telemetry/v2/config/insightsGroup/{ig_name}/fabric/%s/prechangeAnalysis/fileChanges" % site_name
        if not epoch_id:
            base_epoch_data = self.find_closest_epoch(site_name)
        else:
            base_epoch_data = self.get_epoch_by_id(epoch_id)
        data = {"allowUnsupportedObjectModification": True,
                "baseEpochId": base_epoch_data["epochId"],
                "description": "API Triggered PCV",
                "name": datetime.now().strftime("%Y%m%d_%H_%M_%S_DEVNET-1369_PCV"),
                "assuranceEntityName": site_name}
        files = [('data', ('data.json', json.dumps(data), 'application/json')),
                 ('file', (file_name, file_content, mime))]

        result, data = self.generic_post(uri, data, files=files)
        if not result:
            return False
        else:
            return data

    def create_compliance_template_rule(self, name, description, file_content, sites_name, ig_name=None,
                                        tag_match=False):
        """
        :param name:
        :param description:
        :param file_content:
        :param sites_name:
        :param ig_name:
        :param tag_match:
        :return:
        """

        try:
            json.loads(file_content)
            mime = ('application/json', None)
            LOG.debug("PCV file is a valid JSON")
        except json.decoder.JSONDecodeError:
            LOG.error("Compliance Template is not a valid json file")
            return False
        uri = "telemetry/v2/config/insightsGroup/{ig_name}/requirements/file"
        data = {"name": name,
                "description": description,
                "configurationType": "TEMPLATE_BASED_CONFIGURATION_COMPLIANCE",
                "requirementType": "CONFIGURATION_COMPLIANCE",
                "associatedSites": [{"uuid": self.get_site_uuid_by_name(x), "enabled": True} for x in sites_name],
                "enableEqualityCheck": False,
                "uploadedFileName": tag_match,
                "uploadFileType": "TEMPLATE_BASED_CONFIG"}
        files = [('data', ('data.json', json.dumps(data), 'application/json')),
                 ('file', (f"{name}.json", file_content, mime))]
        result, data = self.generic_post(uri, data, files=files)
        if not result:
            return False
        else:
            return data

    def get_compliance_template_file(self, job_name, ig_name=None):
        """
        :param job_id: uuid
        :param ig_name:
        :return:
        """
        uri = "telemetry/v2/config/insightsGroup/{ig_name}/requirements/file/view/%s" % job_name
        result, data = self.generic_get(uri)
        if not result:
            return False
        else:
            return data

    def delete_compliance_template_rule(self, job_id, ig_name=None):
        """
        :param job_id: uuid
        :param ig_name:
        :return:
        """
        uri = "telemetry/v2/config/insightsGroup/{ig_name}/requirements/%s" % job_id
        result, data = self.generic_delete(uri)
        if not result:
            return False
        else:
            return True

    def get_all_template_compliance_rules(self, ig_name=None):
        """
        """
        uri = "/telemetry/v2/config/insightsGroup/{ig_name}/requirements"
        result, data = self.generic_get(uri)
        if not result:
            return False
        else:
            return [x for x in data["value"]["data"] if x["requirementType"] == "CONFIGURATION_COMPLIANCE" and
                    "configurationType" in x.keys() and
                    x["configurationType"] == "TEMPLATE_BASED_CONFIGURATION_COMPLIANCE"]

    def get_epoch_by_id(self):
        """
        """
        pass

    def find_closest_epoch(self, site_name, searched_datetime=None, max_diff=None):
        """
        """
        uri = "telemetry/v2/events/insightsGroup/{ig_name}/fabric/%s/epochs" % site_name
        result, data = self.generic_get(uri)
        if not result:
            return False
        if not searched_datetime:
            # NDI internal time is UTC
            searched_datetime = datetime.now(timezone.utc)
        best_match = None
        best_epoch = None
        for epoch in data["value"]["data"]:
            if not best_match:
                best_match = pyrfc3339.parse(epoch["collectionTimeRfc3339"])
            if (abs((pyrfc3339.parse(epoch["collectionTimeRfc3339"])) - searched_datetime)) <= abs(
                    best_match - searched_datetime):
                best_match = pyrfc3339.parse(epoch["collectionTimeRfc3339"])
                best_epoch = epoch
        if max_diff and abs(best_match - searched_datetime).total_seconds() > max_diff:
            LOG.info(
                f"Best match too far - {str(timedelta(seconds=abs(best_match - searched_datetime).total_seconds()))}")
            return False
        LOG.debug(f"Found a valid Best Epoch {best_match.strftime('%d/%m/%Y %H:%M:%S')}")
        return best_epoch

    def get_anomalies(self, filter=None):
        """
        :param filter: string with NDI compatible filter
                        &fabricName=my_site&filter=category:Compliance AND severity:critical \
                        AND acknowledged:false&insightsGroupName=my_group&
        :return: a list of anomalies
        """

        if not filter:
            uri = f"telemetry/v2/anomalies/details.json"
        else:
            uri = f"telemetry/v2/anomalies/details.json?{filter}"
        result, data = self.generic_get(uri)
        return data["entries"]

    def get_anomaly_affected_objects(self, anomaly_id, site_name, ig_name=None):
        """
        :param anomaly_id:
        :param site_name:
        :param ig_name:
        :return:
        """
        uri = "telemetry/v2/insightsGroup/{ig_name}/fabric/%s/anomalies/affectedObjects.json?anomalyId=%s" % (
            site_name, anomaly_id)
        result, data = self.generic_get(uri)
        if not result:
            return False
        else:
            return data["entries"]

    def start_assurance_analysis(self, site_name, ig_name = None):
        """
        :param site_name:
        :param ig_name:
        :return:
        """
        uri = "telemetry/v2/config/insightsGroup/{ig_name}/fabric/%s/runOnlineAnalysis" % site_name
        result, data = self.generic_post(uri)
        if not result:
            return False
        else:
            return True

    def get_anomaly_details(self, anomaly_id):
        """

        """
        uri = f"/telemetry/v2/anomalies/details.json?&filter=anomalyId:{anomaly_id}"
        result, data = self.generic_get(uri)
        if not result or data["totalResultsCount"] != 1:
            return False
        else:
            return data["entries"][0]

    def get_delta_analysis_by_id(self, site_name, delta_job_id):
        """
        :param delta_job_id:
        :return:
        """
        uri = "/telemetry/v2/epochDelta/insightsGroup/{ig_name}/fabric/%s/job/%s/health/view/eventSeverity" % (
            site_name, delta_job_id)
        result, data = self.generic_get(uri)
        if not result:
            return False
        else:
            return data

    def get_delta_analysis_anomalies(self,site_name, job_name, epoch, severity):
        """
        :param site_name:
        :param job_name:
        :param epoch:
        :param severity:
        :return:
        """

        uri = "telemetry/v2/epochDelta/insightsGroup/{ig_name}/fabric/%s/" \
              "job/%s/health/view/individualTable?$size=100&epochStatus=%s&severity=%s" % (
               site_name, job_name, epoch, severity)

        result, data = self.generic_get(uri)
        if not result:
            return False
        else:
            return data

    def update_anomaly(self, payload, insight_group=None):
        """

        """
        uri = "telemetry/v2/insightsGroup/{ig_name}/alerts/update.json"
        result = self.generic_post(uri, payload=payload)
        if result == 200:
            return True
        else:
            return False
