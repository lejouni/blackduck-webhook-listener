'''
This will parse the event from SRM. When configuring webhook to SRM you need to
get the following info: "descriptions", "results.metadata", "results.vulnerabilities", "aggregations.tool-summary"

Example of adding WebHook to SRM
  {
    "id": 1,
    "name": "BlackDuckTools",
    "enabled": true,
    "payloadUrl": "https://<service_url>/webhook/srm",
    "verifySsl": false,
    "trigger": "finding:status-update",
    "projectScope": "all",
    "expand": [
      "descriptions", "results.metadata", "results.vulnerabilities", "aggregations.tool-summary"
    ]
  }
'''
from utils.SRMInstance import SRMInstance
from utils.Constants import Tools, SRMTools

class SRMParser():
    def __init__(self):
        self.srm = SRMInstance()

    '''
    Parse metadata from the given GHAS event for Black Duck issue update.
    :param event: GHAS event
    '''
    def parseMetadata(self, result, finding):
        metadata = {}
        if result and finding:
            if result["tool"] == SRMTools.BLACK_DUCK:
                metadata = self.__parseforBlackDuck(result, finding)
                metadata["tool"] = Tools.BLACK_DUCK
            elif result["tool"] == SRMTools.COVERITY:
                metadata = self.__parseForCoverity(result, finding)
                metadata["tool"] = Tools.COVERITY
            elif result["tool"] == SRMTools.CNC:
                metadata = self.__parseForCoverity(result, finding)
                metadata["tool"] = Tools.CNC
            else:
                metadata["tool"] = result["tool"]
        metadata["changedBy"] = "SRM"
        metadata["dismiss_reason"] = finding["status"]
        return metadata

    def __parseForCoverity(self, result, finding):
        metadata = {}
        if result["metadata"]["Coverity CID"] and len(result["metadata"]["Coverity CID"]) > 0:
            metadata["cov_cids"] = result["metadata"]["Coverity CID"].split(",")
        elif result["metadata"]["Coverity Merge Key"] and len(result["metadata"]["Coverity Merge Key"]) > 0:
            metadata["cov_merge_keys"] = result["metadata"]["Coverity Merge Key"].split(",")
        metadata["cov_stream"] = result["metadata"]["Coverity Stream"]
        metadata["cov_status"] = self.__statusMappingforCoverity(finding["status"])
        metadata["cov_comment"] = self.srm.getRemediationComments(finding["id"], finding["projectId"], True)
        return metadata

    def __parseforBlackDuck(self, result, finding):
        metadata = {}
        metadata["bd_project_name"] = result["metadata"]["Black Duck Project"].split(":")[0]
        metadata["bd_project_version_name"] = result["metadata"]["Black Duck Project"].split(":")[-1]
        metadata["bd_component_name"] = f'{result["metadata"]["Black Duck Component Name"] if "Black Duck Component Name" in result["metadata"] else None}'
        metadata["bd_component_origin"] = f'{result["metadata"]["Component Identifier"] if "Component Identifier" in result["metadata"] else None}'
        metadata["bd_component_version_name"] = f'{result["metadata"]["Black Duck Component Version"] if "Black Duck Component Version" in result["metadata"] else None}'
        metadata["bd_issue_type"] = str(result["metadata"]["Black Duck Issue Type"]).lower()

        if metadata["bd_issue_type"] == "security":
            vulnerabilities = []
            if result["vulnerabilities"]:
                for vulnerability in result["vulnerabilities"]:
                    vulnerabilities.append(vulnerability["identifier"])
            metadata["vulnerabilities"] = vulnerabilities
            metadata["vulnerability_status"] = self.__statusMappingforBlackDuck(finding["status"])
            metadata["all_comments"] = self.srm.getRemediationComments(finding["id"], finding["projectId"])
        elif metadata["bd_issue_type"] == "policy":
            metadata["bd_policy_name"] = result["descriptor"]["name"]
            metadata["policy_status"] = self.__getPolicyStatus(finding["status"])
            metadata["policy_reason"] = finding["status"]
            metadata["newest_comment"] = self.srm.getRemediationComments(finding["id"], finding["projectId"], True)
        elif metadata["bd_issue_type"] == "iac":
            metadata["bd_iac_checkerID"] = result["metadata"]["Black Duck IaC Checker"]
            metadata["iac_status"] = self.__getIaCStatus(finding["status"])
        return metadata

    def __getPolicyStatus(self, findingStatus):
        if findingStatus:
            if not findingStatus == "reopened":
                return "IN_VIOLATION_OVERRIDDEN"
        return "IN_VIOLATION"

    def __getIaCStatus(self, findingStatus):
        if findingStatus:
            if not findingStatus == "reopened":
                return True
        return False
    
    def __statusMappingforCoverity(self, remediationStatus):
        switcher = { 
            "not-triaged": "Unclassified", 
            "false-positive": "False Positive", 
            "ignored": "Intentional", 
            "to-be-fixed": "Pending", 
            "fixed": "Bug", 
            "mitigated": "Intentional", 
            "reopened": "Unclassified"
        }
        return switcher.get(remediationStatus, "Unclassified")
    
    def __statusMappingforBlackDuck(self, remediationStatus):
        switcher = { 
            "not-triaged": "NEW", 
            "false-positive": "IGNORED", 
            "ignored": "IGNORED", 
            "to-be-fixed": "NEEDS_REVIEW", 
            "fixed": "IGNORED", 
            "mitigated": "MITIGATED", 
            "reopened": "NEW"
        }
        return switcher.get(remediationStatus, "NEW")