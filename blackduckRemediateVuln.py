'''
This will require that Sarif format findings are created via blackduck-sarif-formatter (https://github.com/synopsys-sig-community/blackduck-sarif-formatter).
Blackduck-sarif-formatter will add \"Metadata\" -section to Black Duck finding, which will contain all the needed values for
finging the same issue from Black Duck when GHAS finding status is changed and this webhook will try to update the status to Black Duck.
'''
import logging
import sys
from blackduck.HubRestApi import HubInstance
import requests

__author__ = "Jouni Lehto"
__versionro__="0.0.4"
bd_url=""
bd_access_token=""

class BlackDuckRemediator:
    def __init__(self, log_level=logging.DEBUG):
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("blackduck.HubRestApi").setLevel(logging.WARNING)
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=log_level)
        #Printing out the version number
        logging.debug("Black Duck Remediator version: " + __versionro__)
        #Removing / -mark from end of url, if it exists
        url = f'{bd_url if not bd_url.endswith("/") else bd_url[:-1]}'
        self.hub = HubInstance(url, api_token=bd_access_token, insecure=False)

    '''
    Handle GHAS Black Duck events.
    :param remediation_event: GHAS event
    '''
    def handleEvent(self, remediation_event):
        success = False
        metadata = self.__parseMetadata(remediation_event)
        if metadata:
            projectVersionName = remediation_event["alert"]["most_recent_instance"]["ref"].split("/")[-1]
            projectName = remediation_event["repository"]["full_name"]
            if metadata['bd_issue_type'] == "SECURITY":
                #NOTE Black will need black duck projectName, projectVersionName, componentName, componentVersionName, vulnerabilityName, remediationStatus, remediationComment, dismissedBy
                success = self.__remediate(projectName, projectVersionName, metadata['bd_component_name'],metadata['bd_component_version_name'],
                                            metadata['bd_vulnerability_name'],remediation_event["sender"]["login"], remediation_event["alert"]["dismissed_reason"], remediation_event["alert"]["dismissed_comment"])
            elif metadata['bd_issue_type'] == "POLICY":
                #NOTE projectName, projectVersionName, componentName, componentVersionName, policyName, approvalStatus, dismissedBy, reason, comment="-", overrideExpiresAt=None
                success = self.__updatePolicyStatus(projectName, projectVersionName, metadata['bd_component_name'],
                                                        metadata['bd_component_version_name'], metadata['bd_policy_name'], 
                                                        f'{"IN_VIOLATION_OVERRIDDEN" if remediation_event["action"] == "closed_by_user" else "IN_VIOLATION"}',
                                                        remediation_event["sender"]["login"], remediation_event["alert"]["dismissed_reason"],remediation_event["alert"]["dismissed_comment"])
            elif metadata['bd_issue_type'] == "IAC":
                #NOTE projectName, projectVersionName, iac_checker, dismissStatus
                success = self.__dismissIaC(projectName, projectVersionName, metadata['bd_iac_checkerID'], 
                                                f'{True if remediation_event["action"] == "closed_by_user" else False}')
        else:
            success = False
            logging.info(f'GitHub event is too old and missing \"Metadata\" -section -> cannot find event from Black Duck!')
        return success

    """
    Remediate Black Duck specific component version issue from given project and project version.
    :param projectName: Black Duck project name
    :param projectVersionName: Black Duck project version name
    :param componentName: Black Duck component name
    :param componentVersionName: Black Duck component version name
    :param vulnerabilityName: Black Duckvulnerability name
    :param remediatedBy: Name who remediated vulnerability
    :param remediationStatus: Remediation status
    :param remediationComment: Remediation comment
    """
    def __remediate(self, projectName, projectVersionName, componentName, componentVersionName, vulnerabilityName, remediatedBy, remediationStatus, remediationComment):
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
                                    remediationData["comment"] = self.__createComment(remediationStatus, remediationComment, remediatedBy)
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
    :param dismissedBy: Name who dismissed the policy violation
    :param reason: Reason for dismissing the policy violation
    :param comment: Remediation comment
    :param overrideExpiresAt: date for overwrite expiration in format example 2024-09-07T00:00:00.000Z
    """
    def __updatePolicyStatus(self, projectName, projectVersionName, componentName, componentVersionName, policyName, approvalStatus, dismissedBy, reason, comment="-", overrideExpiresAt=None):
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
                    remediationData["comment"] = self.__createComment(reason, comment, dismissedBy)
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
    def __dismissIaCbyURL(self, iacURL, dismissStatus):
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

    """
    Will dismiss or reopen the given IaC finding
    :param projectName: Black Duck project name
    :param projectVersionName: Black Duck project version name
    :param iac_checker: IaC checker ID
    :param dismissStatus: True to dismiss and False to reopen
    """
    def __dismissIaC(self, projectName, projectVersionName, iac_checker, dismissStatus):
        parameters={"q":"name:{}".format(projectName)}
        projects = self.hub.get_projects(limit=1, parameters=parameters)
        if projects:
            for project in projects["items"]:
                versions = self.__get_project_versions(project, projectVersionName)
                for version in versions["items"]:
                    url = self.__getIacURL(version, iac_checker)
                    if url:
                        return self.__dismissIaCbyURL(url, dismissStatus)
        return False

    '''
    Parse metadata from the given GHAS event for Black Duck issue update.
    :param remediation_event: GHAS event
    '''
    def __parseMetadata(self, remediation_event):
        metadata = {}
        if remediation_event:
            helpText = remediation_event["alert"]["rule"]["help"]
            if helpText:
                metadatas = helpText.split("Metadata\n")[-1].split('\n')
                if metadatas:
                    for data in metadatas:
                        if str(data).startswith("**Black Duck Issue Type:**"):
                            metadata['bd_issue_type'] = data.split(':**')[-1].strip()
                        elif str(data).startswith("**Black Duck Vulnerability Name:**"):
                            metadata['bd_vulnerability_name'] = data.split(':**')[-1].strip()
                        elif str(data).startswith("**Black Duck Component Name:**"):
                            metadata['bd_component_name'] = data.split(':**')[-1].strip()
                        elif str(data).startswith("**Black Duck Component Version:**"):
                            metadata['bd_component_version_name'] = data.split(':**')[-1].strip()
                        elif str(data).startswith("**Black Duck Policy Name:**"):
                            metadata['bd_policy_name'] = data.split(':**')[-1].strip()
                        elif str(data).startswith("**Black Duck IaC Checker:**"):
                            metadata['bd_iac_checkerID'] = data.split(':**')[-1].strip()
        return metadata
    
    def __getIacURL(self, projectVersion, iac_checker):
        if projectVersion:
            iacFindings = self.__getIACFindings(projectVersion)
            for iacFinding in iacFindings:
                if iacFinding["checkerId"] == iac_checker:
                    return iacFinding["_meta"]["href"]

    def __getIACFindings(self, projectVersion):
        MAX_LIMT_IAC = 25
        all_iac_findings = []
        url = f'{projectVersion["_meta"]["href"]}/iac-issues?limit={MAX_LIMT_IAC}&offset=0'
        headers = self.hub.get_headers()
        headers['Accept'] = 'application/vnd.blackducksoftware.internal-1+json, application/json'
        response = requests.get(url, headers=headers, verify = not self.hub.config['insecure'])
        if response.status_code == 200:
            result = response.json()
            if "totalCount" in result:
                total = result["totalCount"]
                all_iac_findings = result["items"]
                downloaded = MAX_LIMT_IAC
                while total > downloaded:
                    logging.debug(f"getting next page {downloaded}/{total}")
                    url = f'{projectVersion["_meta"]["href"]}/iac-issues?limit={MAX_LIMT_IAC}&offset={downloaded}'
                    headers = self.hub.get_headers()
                    headers['Accept'] = 'application/vnd.blackducksoftware.internal-1+json, application/json'
                    response = requests.get(url, headers=headers, verify = not self.hub.config['insecure'])
                    all_iac_findings.extend(response.json()['items'])
                    downloaded += MAX_LIMT_IAC
        return all_iac_findings        

    def __createComment(self, reason, comment, dismissedBy):
        policyComment = ""
        if reason:
            policyComment = f'Reason to dismiss: {reason}\n'
        if comment:
            policyComment = f'{policyComment}Dismissal comment: {comment}\n'
        if dismissedBy:
            policyComment = f'{policyComment}Changed by: {dismissedBy}'
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
        remediator = BlackDuckRemediator(bd_url,bd_access_token)
        #DUPLICATE, IGNORED, MITIGATED, NEEDS_REVIEW, NEW, PATCHED, REMEDIATION_COMPLETE, REMEDIATION_REQUIRED
        #IN_VIOLATION_OVERRIDDEN, IN_VIOLATION
        logging.debug(remediator.updatePolicyStatus("lejouni/sampleapp", "main", "Restcomm", "1.0.41", "No External Projects With Reciprocal Licenses", "IN_VIOLATION_OVERRIDDEN", "won't fix", "Will upgrade on next sprint.", "2024-09-07T00:00:00.000Z"))
        # logging.debug(remediator.dismissIaC("https://testing.blackduck.synopsys.com/api/projects/5238adb2-d99a-4649-baf8-494589bcdb9e/versions/fabd4412-9eb6-44a2-b583-bd81c4f9c98b/iac-issues/16e67b88-fa9b-36d3-b7ed-b4d1389d73ec", True))
    except Exception as e:
        logging.exception(e)
        raise SystemError(e)
