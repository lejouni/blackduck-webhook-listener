import logging
import sys
from blackduck.HubRestApi import HubInstance
import requests
import json

__author__ = "Jouni Lehto"
__versionro__="0.0.3"

class BlackDuckRemediator:
    def __init__(self, url, token, log_level=logging.DEBUG):
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("blackduck.HubRestApi").setLevel(logging.WARNING)
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=log_level)
        #Printing out the version number
        logging.debug("Black Duck Remediator version: " + __versionro__)
        #Removing / -mark from end of url, if it exists
        url = f'{url if not url.endswith("/") else url[:-1]}'
        self.hub = HubInstance(url, api_token=token, insecure=False)

    """
    Remediate Black Duck specific component version issue from given project and project version.
    :param projectName: Black Duck project name
    :param projectVersionName: Black Duck project version name
    :param componentName: Black Duck component name
    :param componentVersionName: Black Duck component version name
    :param vulnerabilityName: Black Duckvulnerability name
    :param remediationStatus: Remediation status
    :param remediationComment: Remediation comment
    """
    def remediate(self, projectName, projectVersionName, componentName, componentVersionName, vulnerabilityName, remediationStatus, remediationComment):
        logging.debug(f'remediate with params: {projectName},{projectVersionName},{componentName},{componentVersionName},{vulnerabilityName},{remediationStatus},{remediationComment} ')
        parameters={"q":"name:{}".format(projectName)}
        projects = self.hub.get_projects(limit=1, parameters=parameters)
        for project in projects["items"]:
            versions = self.__get_project_versions(project, projectVersionName)
            for version in versions["items"]:
                headers = self.hub.get_headers()
                headers['Accept'] = 'application/vnd.blackducksoftware.bill-of-materials-6+json'
                parameters={"q":"componentName:{},vulnerabilityName:{}".format(componentName,vulnerabilityName)}
                url = version['_meta']['href']+"/vulnerable-bom-components" + self.hub._get_parameter_string(parameters)
                response = requests.get(url, headers=headers, verify = not self.hub.config['insecure'])
                if response.status_code == 200:
                    vulnComps = response.json()
                    if vulnComps["totalCount"] > 0:
                        for vulnComp in vulnComps["items"]:
                            logging.debug(vulnComp)
                            if vulnComp["componentName"] == componentName and vulnComp["componentVersionName"] == componentVersionName:
                                url = vulnComp['_meta']['href']
                                response = requests.get(url, headers=headers, verify = not self.hub.config['insecure'])
                                if response.status_code == 200:
                                    remediationData = {}
                                    remediationData["comment"] = f'{remediationComment if remediationComment else "-"}'
                                    remediationData["remediationStatus"]= self.__checkRemediationStatusMapping(remediationStatus)
                                    logging.debug(f'Updating component status with: {remediationData}')
                                    response = requests.put(url, headers=headers, json=remediationData, verify = not self.hub.config['insecure'])
                                    if response.status_code == 202:
                                        return True
                                    else:
                                        logging.error(f"Remediation status update failed: {response}/{response.content}")
                    else:
                        logging.error(f'No vulnerable component found with name: {componentName} and vulnerability name: {vulnerabilityName}')
        return False
                
    """
    Will overwrite policy violation from given project and project version.
    :param projectName: Black Duck project name
    :param projectVersionName: Black Duck project version name
    :param componentName: Black Duck component name
    :param componentVersionName: Black Duck component version name
    :param policyName: Policy name which will be overwritten. Component might have several policy violations, this will identify the right one.
    :param approvalStatus: Remediation status
    :param comment: Remediation comment
    :param overrideExpiresAt: date for overwrite expiration in format example 2024-09-07T00:00:00.000Z
    """
    def updatePolicyStatus(self, projectName, projectVersionName, componentName, componentVersionName, policyName, approvalStatus, reason, comment="-", overrideExpiresAt=None):
        if projectName and projectVersionName and componentName and componentVersionName:
            parameters={"q":"name:{}".format(projectName)}
            projects = self.hub.get_projects(limit=1, parameters=parameters)
            for project in projects["items"]:
                versions = self.__get_project_versions(project, projectVersionName)
                for version in versions["items"]:
                    headers = self.hub.get_headers()
                    headers['Accept'] = 'application/vnd.blackducksoftware.bill-of-materials-6+json'
                    headers['Content-Type'] = 'application/vnd.blackducksoftware.bill-of-materials-6+json'
                    remediationData = {}
                    remediationData["comment"] = self.__createComment(reason, comment)
                    remediationData["approvalStatus"] = approvalStatus
                    remediationData["overrideExpiresAt"] = overrideExpiresAt
                    logging.debug(f'Updating component policy status with: {remediationData}')
                    url = self.__get_version_component_url(version, componentName, componentVersionName)
                    if url:
                        response = requests.get(url, headers=headers, verify = not self.hub.config['insecure'])
                        if response.status_code == 200:
                            policies = response.json()
                            for policy in policies["items"]:
                                if policy["name"] == policyName:
                                    policyRuleID = policy["_meta"]["href"].split('/')[-1]
                                    response = requests.put(f'{url}/{policyRuleID}/policy-status', headers=headers, json=remediationData, verify = not self.hub.config['insecure'])
                                    if response.status_code == 202:
                                        return True
                                    else:
                                        logging.error(f"Policy overwrite failed: {response}/{response.content}")
        return False

    """
    Will dismiss or reopen the given IaC finding
    :param iacURL: URL contains the whole path to Black Duck IaC finding.
    :param dismissStatus: True to dismiss and False to reopen
    """
    def dismissIaC(self, iacURL, dismissStatus):
        if iacURL:
            headers = self.hub.get_headers()
            headers['Content-Type'] = 'application/vnd.blackducksoftware.bill-of-materials-6+json'
            remediationData = {"ignored": dismissStatus}
            response = requests.put(iacURL, headers=headers, json=remediationData, verify = not self.hub.config['insecure'])
            if response.status_code == 204:
                return True
            else:
                logging.error(f"IaC finding {iacURL} failed: {response}/{response.content}")
        return False


    def __createComment(self, reason, comment):
        policyComment = ""
        if reason:
            policyComment = f'Reason to dismiss: {reason}\n'
        if comment:
            policyComment = f'{policyComment}Dismissal Reason: {comment}'
        return policyComment

    def __get_version_component_url(self, projectversion, componentName, componentVersionName, limit=10):
        parameters={"limit": limit, "q":"componentOrVersionName:{}".format(componentName)}
        url = projectversion['_meta']['href'] + "/components"
        headers = self.hub.get_headers()
        headers['Accept'] = 'application/vnd.blackducksoftware.bill-of-materials-6+json'
        response = requests.get(url, headers=headers, params=parameters, verify = not self.hub.config['insecure'])
        if response.status_code == 200:
            jsondata = response.json()
            if jsondata["totalCount"] > 0:
                for item in jsondata["items"]:
                    if item["componentName"] == componentName and item["componentVersionName"] == componentVersionName:
                        return self.__getLinksparam(item, "policy-rules", "href")
        else:
            logging.error(f"__get_version_components failed: {response}/{response.content}")

    def __getLinksparam(self, data, relName, param):
        for metadata in data['_meta']['links']:
            if metadata['rel'] == relName:
                return metadata[param]

    def __get_project_versions(self, project, projectVersionName):
        parameters={'q':"versionName:{}".format(projectVersionName)}
        parameters.update({'limit': 1})
        url = project['_meta']['href'] + "/versions" + self.hub._get_parameter_string(parameters)
        headers = self.hub.get_headers()
        headers['Accept'] = 'application/vnd.blackducksoftware.internal-1+json'
        response = requests.get(url, headers=headers, verify = not self.hub.config['insecure'])
        jsondata = response.json()
        return jsondata

    def __checkRemediationStatusMapping(self, remediationStatus):
        switcher = { 
            "false positive": "IGNORED", 
            "used in tests": "IGNORED",
            "won't fix": "IGNORED" 
        }
        return switcher.get(remediationStatus, "NEW")
    
#Main method is only for testing the script without the webhook integration
if __name__ == '__main__':
    try:
        remediator = BlackDuckRemediator("https://testing.blackduck.synopsys.com","")
        #DUPLICATE, IGNORED, MITIGATED, NEEDS_REVIEW, NEW, PATCHED, REMEDIATION_COMPLETE, REMEDIATION_REQUIRED
        #IN_VIOLATION_OVERRIDDEN, IN_VIOLATION
        logging.debug(remediator.updatePolicyStatus("lejouni/sampleapp", "main", "Restcomm", "1.0.41", "No External Projects With Reciprocal Licenses", "IN_VIOLATION_OVERRIDDEN", "won't fix", "Will upgrade on next sprint.", "2024-09-07T00:00:00.000Z"))
        # logging.debug(remediator.dismissIaC("https://testing.blackduck.synopsys.com/api/projects/5238adb2-d99a-4649-baf8-494589bcdb9e/versions/fabd4412-9eb6-44a2-b583-bd81c4f9c98b/iac-issues/16e67b88-fa9b-36d3-b7ed-b4d1389d73ec", True))
    except Exception as e:
        logging.exception(e)
        raise SystemError(e)
