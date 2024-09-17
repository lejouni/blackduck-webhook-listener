from SRMInstance import SRMInstance
from Constants import Tools, SRMTools

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
        return metadata

    def __parseForCoverity(self, result, finding):
        metadata = {}
        if result["metadata"]["Coverity CID"] and len(result["metadata"]["Coverity CID"]) > 0:
            metadata["cov_cids"] = result["metadata"]["Coverity CID"].split(",")
        elif result["metadata"]["Coverity Merge Key"] and len(result["metadata"]["Coverity Merge Key"]) > 0:
            metadata["cov_merge_keys"] = result["metadata"]["Coverity Merge Key"].split(",")
        metadata["cov_stream"] = result["metadata"]["Coverity Stream"]
        metadata["cov_status"] = finding["status"]
        metadata["cov_comment"] = self.srm.getRemediationComments(finding["id"], finding["projectId"], True)
        return metadata

    def __parseforBlackDuck(self, result, finding):
        metadata = {}
        metadata["bd_project_name"] = result["metadata"]["Black Duck Project"].split(":")[0]
        metadata["bd_project_version_name"] = result["metadata"]["Black Duck Project"].split(":")[-1]
        metadata["bd_component_name"] = f'{result["metadata"]["Black Duck Component Name"] if "Black Duck Component Name" in result["metadata"] else None}'
        metadata["bd_component_version_name"] = f'{result["metadata"]["Black Duck Component Version"] if "Black Duck Component Version" in result["metadata"] else None}'
        metadata["bd_issue_type"] = str(result["metadata"]["Black Duck Issue Type"]).lower()
        metadata["changedBy"] = "SRM"

        if metadata["bd_issue_type"] == "security":
            vulnerabilities = []
            if result["vulnerabilities"]:
                for vulnerability in result["vulnerabilities"]:
                    vulnerabilities.append(vulnerability["identifier"])
            metadata["vulnerabilities"] = vulnerabilities
            metadata["vulnerabilitys_status"] = finding["status"]
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
