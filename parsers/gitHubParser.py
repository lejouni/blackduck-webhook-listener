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
            metadata["action_allowed"] = False
            if event["trigger"] == "finding:status-update":
                metadata["action_allowed"] = True
            metadata["changedBy"] = event["sender"]["login"]
            metadata["action_allowed"] = False
            if event["action"] == "closed_by_user" or event["action"] == "reopened_by_user":
                metadata["action_allowed"] = True
        return metadata

    def __parseForCoverity(self, event):
        metadata = {}
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
            metadata["vulnerabilitys_status"] = event["alert"]["dismissed_reason"]
            metadata["all_comments"] = event["alert"]["dismissed_comment"]
        elif str(metadata["bd_issue_type"]).lower() == "policy":
            metadata["policy_status"] = f'{"IN_VIOLATION_OVERRIDDEN" if event["action"] == "closed_by_user" else "IN_VIOLATION"}'
            metadata["policy_reason"] = event["alert"]["dismissed_reason"]
            metadata["newest_comment"] = event["alert"]["dismissed_comment"]
        elif str(metadata["bd_issue_type"]).lower() == "iac":
            metadata["bd_iac_checkerID"] = metadata['bd_iac_checkerID']
            metadata["iac_status"] = f'{True if event["action"] == "closed_by_user" else False}'
        return metadata
