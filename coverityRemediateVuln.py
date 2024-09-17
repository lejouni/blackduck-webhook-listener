import logging
import sys
import requests
import json
from SRMInstance import SRMInstance
from SecretManager import SecretManager

__author__ = "Jouni Lehto"
__versionro__="0.0.5"

class CoverityRemediator:
    def __init__(self, log_level=logging.INFO):
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=log_level)
        #Printing out the version number
        logging.debug("Coverity Remediator version: " + __versionro__)
        cov_url = SecretManager().get_secret("COVERITY")["COVURL"]
        #Removing / -mark from end of url, if it exists
        self.url = f'{cov_url if not cov_url.endswith("/") else cov_url[:-1]}'
        self.username = SecretManager().get_secret("COVERITY")["COV_USERNAME"]
        self.password = SecretManager().get_secret("COVERITY")["COV_PASSWORD"]
        self.srm = SRMInstance()

    """
    Remediate Coverity specific issue.
    :param finding: SRM Finding
    :param result: SRM one evidence of the finding in SRM
    """
    def updateStatus(self, metadata):
        success = False
        #NOTE Coverity remediation endpoint will need: CIDs, mergeKeys, streamName, remediationStatus, remediationComment
        #NOTE Script will use CIDs if they are given otherwise mergeKeys. Stream name is used to figure out the needed triage store name.
        if metadata["cov_cids"]:
            success = self.__remediate(metadata["cov_cids"], None, metadata["cov_stream"], metadata["cov_status"], metadata["cov_comment"])
        elif metadata["cov_merge_keys"]:
            success = self.__remediate(None, metadata["cov_merge_keys"], metadata["cov_stream"], metadata["cov_status"], metadata["cov_comment"])
        else:
            logging.error("Finding was missing CID and Merge Key. Issue has to have some of them!")
        return success

    """
    Remediate given issue from Coverity for given stream. Issues can be given with CIDs or with mergeKeys.
    :param CIDs: Coverity IDs for issues to be remediated. List of CIDs as a String format.
    :param mergeKeys: Coverity IDs for issues to be remediated. List of mergeKeys as a String format.
    :param streamName: Stream name which the project is using.
    :param remediationStatus: Remediation status
    :param remediationComment: Remediation comment
    """
    def __remediate(self, CIDs, mergeKeys, streamName, remediationStatus, remediationComment):
        triageStore = self.__getTriageStoreForStream(streamName)
        if triageStore:
            headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
            endpoint = f'/api/v2/issues/triage?triageStoreName={triageStore}'
            remediationData = {}
            if CIDs and len(CIDs) > 0:
                remediationData["cids"] = CIDs
            elif mergeKeys and len(mergeKeys) > 0:
                remediationData["mergeKeys"] = mergeKeys
            remediationData["attributeValuesList"] = [{"attributeName": "Classification", "attributeValue": self.__checkRemediationStatusMapping(remediationStatus)}, 
                                                      {"attributeName": "comment", "attributeValue": remediationComment}]
            response = requests.put(self.url + endpoint, headers=headers, data=json.dumps(remediationData), auth=(self.username, self.password))
            if response and response.status_code == 200:
                return True
            else:
                logging.error(response.text)
        else:
            logging.error(f'Triage store not found for given stream: {streamName}')
        return False
            
    
    def __getTriageStoreForStream(self, stream_name):
        headers = {'Accept': 'application/json'}
        endpoint = f'/api/v2/streams/{stream_name}?locale=en_us'
        response = requests.get(self.url + endpoint, headers=headers, auth=(self.username, self.password))
        if response and response.status_code == 200:
            for stream in response.json()["streams"]:
                if stream["name"] == stream_name:
                    if "triageStoreName" in stream and stream["triageStoreName"]:
                        return stream["triageStoreName"]
                    else:
                        return None
        return None

    def __checkRemediationStatusMapping(self, remediationStatus):
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

#Main method is only for testing the script without the webhook integration
if __name__ == '__main__':
    try:
        remediator = CoverityRemediator()
        #Unclassified, Pending, False Positive, Intentional, Bug
        logging.debug(remediator.remediate([eval(i) for i in ["607367"]], "", "sampleapp-feature", "Ignored", "This is how we need to do it."))
        logging.info("Done")
    except Exception as e:
        logging.exception(e)
        raise SystemError(e)
