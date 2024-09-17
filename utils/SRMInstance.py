import logging
import sys
import requests
from dateutil.parser import parse
from utils.SecretManager import SecretManager

class SRMInstance:
    def __init__(self, log_level=logging.DEBUG):
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=log_level)
        srm_url = SecretManager().get_secret("SRM")["SRM_URL"]
        #Removing / -mark from end of url, if it exists
        self.url = f'{srm_url if not srm_url.endswith("/") else srm_url[:-1]}'
        self.token = SecretManager().get_secret("SRM")["SRMTOKEN"]
    
    def getRemediationComments(self, findingID, projectID, newestOnly=False):
        comments = None #self.__getFindingComments(findingID, projectID)
        modified_comments = "Changed by SRM"
        if comments:
            modified_comments = ""
            if not newestOnly:
                for comment in comments:
                    modified_comments = modified_comments + f'{comment["createdAt"]} by {comment["user.name"]}: {comment["content"]}' + "\n"
            else:
                modified_comments = modified_comments + f'{comments[0]["createdAt"]} by {comments[0]["user.name"]}: {comments[0]["content"]}' + "\n"
        return modified_comments

    def __getHeaders(self):
        headers = {
            "API-Key": self.token,
            "Accept": "application/json"
        }
        return headers
    
    def __getFindingHistory(self, findingID, projectID):
        if findingID and projectID:
            endpoint = f"/x/projects/{projectID}/findings/{findingID}/history"
            response = requests.get(self.url + endpoint, headers=self.__getHeaders())
            if response.status_code == 200:
                return response.json()
            else:
                logging.error(f"getFindingHistory failed: {response}/{response.json()}")
        else:
            logging.error(f"findingID or projectID was not given and both are required.")

    def __getFindingComments(self, findingID, projectID, reverse=True, timeformat="%y-%m-%d %H:%M:%S"):
        findingHistories = self.__getFindingHistory(findingID, projectID)
        if findingHistories:
            findingComments = []
            for findingHistory in findingHistories:
                if findingHistory["type"] == "finding-comment":
                    findingComments.append({"createdAt":self.__formatDateTime(findingHistory["data"]["createdAt"], timeformat), 
                                            "content":findingHistory["data"]["content"],
                                            "user.name":findingHistory["data"]["user"]["name"]})
            return sorted(findingComments, key=lambda comment: comment['createdAt'], reverse=reverse)
        
    def __formatDateTime(self, dateTimeToFormat, format):
        if dateTimeToFormat:
            return str(parse(dateTimeToFormat).strftime(format))

if __name__ == '__main__':
    try:
        srm = SRMInstance()
        logging.debug(srm.__getFindingComments("58", "1"))
        logging.info("Done")
    except Exception as e:
        logging.exception(e)
        raise SystemError(e)
