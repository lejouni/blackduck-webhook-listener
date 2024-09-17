import logging
import sys
from blackduck.HubRestApi import HubInstance
import requests
from utils.SecretManager import SecretManager

__author__ = "Jouni Lehto"
__versionro__="0.0.5"

class BlackDuckRemediator:
    def __init__(self, log_level=logging.DEBUG):
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("blackduck.HubRestApi").setLevel(logging.WARNING)
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=log_level)
        #Printing out the version number
        logging.debug("Black Duck Remediator version: " + __versionro__)
        bd_url = SecretManager().get_secret("BLACKDUCK")["BLACKDUCK_SERVER_URL"]
        #Removing / -mark from end of url, if it exists
        url = f'{bd_url if not bd_url.endswith("/") else bd_url[:-1]}'
        self.hub = HubInstance(url, api_token=SecretManager().get_secret("BLACKDUCK")["BLACKDUCK_ACCESSTOKEN"], insecure=False)

    '''
    Handle the Black Duck events.
    :param metadata: contains needed info. Collected by using correct parses (GitHubParser or SRMParser)
    '''
    def updateStatus(self, metadata):
        success = False
        if metadata:
            if str(metadata['bd_issue_type']).lower() == "security":
                #NOTE Black will need black duck projectName, projectVersionName, componentName, componentVersionName, vulnerabilityName, remediationStatus, remediationComment, dismissedBy
                success = self.__remediate(metadata['bd_project_name'], metadata['bd_project_version_name'], metadata['bd_component_name'],metadata['bd_component_version_name'],
                                            metadata['bd_vulnerability_name'],metadata["changedBy"], metadata["vulnerabilitys_status"], metadata["all_comments"])
            elif str(metadata['bd_issue_type']).lower() == "policy":
                #NOTE projectName, projectVersionName, componentName, componentVersionName, policyName, approvalStatus, dismissedBy, reason, comment="-", overrideExpiresAt=None
                success = self.__updatePolicyStatus(metadata['bd_project_name'], metadata['bd_project_version_name'], metadata['bd_component_name'],
                                                        metadata['bd_component_version_name'], metadata['bd_policy_name'], 
                                                        metadata["policy_status"], metadata["changedBy"], metadata["policy_reason"],metadata["newest_comment"])
            elif str(metadata['bd_issue_type']).lower() == "iac":
                #NOTE projectName, projectVersionName, iac_checker, dismissStatus
                success = self.__dismissIaC(metadata['bd_project_name'], metadata['bd_project_version_name'], metadata['bd_iac_checkerID'], metadata["iac_status"])
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
                        elif str(data).startswith("**Black Duck Project Name:**"):
                            metadata['bd_project_name'] = data.split(':**')[-1].strip()
                        elif str(data).startswith("**Black Duck Project Version Name:**"):
                            metadata['bd_project_version_name'] = data.split(':**')[-1].strip()
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
