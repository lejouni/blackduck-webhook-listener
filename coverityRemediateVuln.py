import logging
import sys
import requests
import json

__author__ = "Jouni Lehto"
__versionro__="0.0.2"


class CoverityRemediator:
    def __init__(self, url, username, password, log_level=logging.INFO):
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=log_level)
        #Printing out the version number
        logging.debug("Coverity Remediator version: " + __versionro__)
        #Removing / -mark from end of url, if it exists
        self.url = f'{url if not url.endswith("/") else url[:-1]}'
        self.username = username
        self.password = password

    """
    Remediate given issue from Coverity for given stream. Issues can be given with CIDs or with mergeKeys.
    :param CIDs: Coverity IDs for issues to be remediated. List of CIDs as a String format.
    :param mergeKeys: Coverity IDs for issues to be remediated. List of mergeKeys as a String format.
    :param streamName: Stream name which the project is using.
    :param remediationStatus: Remediation status
    :param remediationComment: Remediation comment
    """
    def remediate(self, CIDs, mergeKeys, streamName, remediationStatus, remediationComment):
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
                                                      {"attributeName": "comment", "attributeValue": f'{remediationComment if remediationComment else "-"}'}]
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
            "false positive": "False Positive", 
            "used in tests": "Intentional",
            "won't fix": "Intentional" 
        }
        return switcher.get(remediationStatus, "Unclassified")

#Main method is only for testing the script without the webhook integration
if __name__ == '__main__':
    try:
        remediator = CoverityRemediator("https://demo.coverity.synopsys.com", "<username>", "<password>")
        #Unclassified, Pending, False Positive, Intentional, Bug
        logging.debug(remediator.remediate([eval(i) for i in ["607367"]], "", "sampleapp-feature", "Ignored", "This is how we need to do it."))
        logging.info("Done")
    except Exception as e:
        logging.exception(e)
        raise SystemError(e)
