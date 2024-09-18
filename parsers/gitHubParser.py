'''
This will require that Sarif format findings are created via blackduck-sarif-formatter (https://github.com/synopsys-sig-community/blackduck-sarif-formatter).
Blackduck-sarif-formatter will add \"Metadata\" -section to Black Duck finding, which will contain all the needed values for
finging the same issue from Black Duck when GHAS finding status is changed and this webhook will try to update the status to Black Duck.
'''
from utils.Constants import Tools, GitHubTools

class GitHubParser():
    def __init__(self):
        pass

    '''
    Parse metadata from the given GHAS event for Black Duck issue update.
    :param event: GHAS event
    '''
    def parseMetadata(self, event):
        metadata = {}
        if event:
            if event["alert"]["tool"]["name"] == GitHubTools.BLACK_DUCK:
                metadata = self.__parseforBlackDuck(event)
                metadata["tool"] = Tools.BLACK_DUCK
            elif event["alert"]["tool"]["name"] == GitHubTools.COVERITY:
                metadata = self.__parseForCoverity(event)
                metadata["tool"] = Tools.COVERITY
            elif event["alert"]["tool"]["name"] == GitHubTools.CNC:
                metadata = self.__parseForCoverity(event)
                metadata["tool"] = Tools.CNC
            else:
                metadata["tool"] = event["alert"]["tool"]["name"]
            metadata["changedBy"] = event["sender"]["login"]
            metadata["dismiss_reason"] = event["alert"]["dismissed_reason"]
            if "action" in event:
                if event["action"] == "closed_by_user" or event["action"] == "reopened_by_user":
                    metadata["action_allowed"] = True
            else:
                metadata["action_allowed"] = False
        return metadata

    def __parseForCoverity(self, event):
        metadata = {}
        helpText = event["alert"]["rule"]["help"]
        if helpText:
            metadatas = helpText.split("Metadata\n")[-1].split('\n')
            if metadatas:
                for data in metadatas:
                    if str(data).startswith("**Coverity Project Name:**"):
                        metadata['cov_project'] = data.split(':**')[-1].strip()
                    elif str(data).startswith("**Coverity Stream:**"):
                        metadata['cov_stream'] = data.split(':**')[-1].strip()
                    elif str(data).startswith("**Coverity CID:**"):
                        metadata['cov_cids'] = data.split(':**')[-1].strip().split(",")
            metadata["cov_status"] = self.__checkStatusMappingCoverity(event["alert"]["dismissed_reason"])
            metadata["cov_comment"] = event["alert"]["dismissed_comment"]
        return metadata

    def __parseforBlackDuck(self, event):
        metadata = {}
        helpText = event["alert"]["rule"]["help"]
        if helpText:
            metadatas = helpText.split("Metadata\n")[-1].split('\n')
            vulnerabilities = []
            if metadatas:
                for data in metadatas:
                    if str(data).startswith("**Black Duck Issue Type:**"):
                        metadata['bd_issue_type'] = data.split(':**')[-1].strip()
                    elif str(data).startswith("**Black Duck Project Name:**"):
                        metadata['bd_project_name'] = data.split(':**')[-1].strip()
                    elif str(data).startswith("**Black Duck Project Version Name:**"):
                        metadata['bd_project_version_name'] = data.split(':**')[-1].strip()
                    elif str(data).startswith("**Black Duck Vulnerability Name:**"):
                        vulnerabilities.append(data.split(':**')[-1].strip())
                        metadata["vulnerabilities"] = vulnerabilities
                    elif str(data).startswith("**Black Duck Component Name:**"):
                        metadata['bd_component_name'] = data.split(':**')[-1].strip()
                    elif str(data).startswith("**Black Duck Component Version:**"):
                        metadata['bd_component_version_name'] = data.split(':**')[-1].strip()
                    elif str(data).startswith("**Black Duck Policy Name:**"):
                        metadata['bd_policy_name'] = data.split(':**')[-1].strip()
                    elif str(data).startswith("**Black Duck IaC Checker:**"):
                        metadata['bd_iac_checkerID'] = data.split(':**')[-1].strip()
        if str(metadata["bd_issue_type"]).lower() == "security":
            metadata["vulnerability_status"] = self.__checkStatusMappingBlacDuck(event["alert"]["dismissed_reason"])
            metadata["all_comments"] = event["alert"]["dismissed_comment"]
        elif str(metadata["bd_issue_type"]).lower() == "policy":
            metadata["policy_status"] = f'{"IN_VIOLATION_OVERRIDDEN" if event["action"] == "closed_by_user" else "IN_VIOLATION"}'
            metadata["policy_reason"] = event["alert"]["dismissed_reason"]
            metadata["newest_comment"] = event["alert"]["dismissed_comment"]
        elif str(metadata["bd_issue_type"]).lower() == "iac":
            metadata["bd_iac_checkerID"] = metadata['bd_iac_checkerID']
            metadata["iac_status"] = f'{True if event["action"] == "closed_by_user" else False}'
        return metadata

    def __checkStatusMappingBlacDuck(self, remediationStatus):
        switcher = { 
            "false positive": "IGNORED", 
            "used in tests": "IGNORED",
            "won't fix": "IGNORED" 
        }
        return switcher.get(remediationStatus, "NEW")

    def __checkStatusMappingCoverity(self, remediationStatus):
        switcher = { 
            "false positive": "False Positive", 
            "used in tests": "Intentional",
            "won't fix": "Intentional" 
        }
        return switcher.get(remediationStatus, "Unclassified")
