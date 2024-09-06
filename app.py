import sys
from flask import Flask, request,  abort
import socket
import logging
from timeit import default_timer as timer
import logging
import sys
import json
from blackduckRemediateVuln import BlackDuckRemediator
from coverityRemediateVuln import CoverityRemediator

__version__="0.0.3"
__author__ = "Jouni Lehto"

app = Flask(__name__)
bd_url="https://testing.blackduck.synopsys.com"
bd_access_token=""
cov_url="https://demo.coverity.synopsys.com"
username=""
password=""

@app.route('/webhook/github/asevents', methods=['POST'])
def webhook():
    try:
        start = timer()
        success = False
        logging.debug(f'request.json: {json.dumps(request.json, indent=3)}')
        remediation_event = request.json
        if remediation_event["action"] == "closed_by_user" or remediation_event["action"] == "reopened_by_user":
            if remediation_event["alert"]["tool"]["name"] == "Synopsys Black Duck Intelligent":
                rule_id = remediation_event["alert"]["rule"]["id"].split(":")
                projectVersionName = remediation_event["alert"]["most_recent_instance"]["ref"].split("/")[-1]
                projectName = remediation_event["repository"]["full_name"]
                #TODO Check is event for vulnerability remediation or for policy overwritten
                remediator = BlackDuckRemediator(bd_url, bd_access_token)
                if len(rule_id) == 3:
                    #NOTE Black will need black duck projectName, projectVersionName, componentName, componentVersionName, vulnerabilityName, remediationStatus, remediationComment
                    success = remediator.remediate(projectName, projectVersionName, rule_id[1],rule_id[2],rule_id[0],remediation_event["alert"]["dismissed_reason"], remediation_event["alert"]["dismissed_comment"])
                elif str(remediation_event["alert"]["rule"]["id"]).startswith("POLICY"):
                    #NOTE projectName, projectVersionName, componentName, componentVersionName, approvalStatus, comment="-", overrideExpiresAt=None
                    success = remediator.updatePolicyStatus(projectName, projectVersionName, rule_id[2], rule_id[3], rule_id[1], 
                                                            f'{"IN_VIOLATION_OVERRIDDEN" if remediation_event["action"] == "closed_by_user" else "IN_VIOLATION"}',
                                                            remediation_event["alert"]["dismissed_reason"],remediation_event["alert"]["dismissed_comment"])
                elif str(remediation_event["alert"]["rule"]["id"]).startswith("IAC"):
                    #NOTE help_uri contains the whole path to iac finding
                    success = remediator.dismissIaC(remediation_event["alert"]["rule"]["help_uri"], 
                                                    f'{True if remediation_event["action"] == "closed_by_user" else False}')
            end = timer()
            usedTime = end - start
            logging.debug(f"Took: {usedTime} seconds.")
            if not success:
                abort(400, "Remediation failed!")
            else:
                return json.dumps({'success':True}), 200, {'ContentType':'application/json'}
        else:
            logging.error(f'Trigger: {remediation_event["action"]} is not currently supported!')    
    except Exception as e:
        logging.exception(e)            
        abort(400, e)

if __name__ == '__main__':
    hostname=socket.gethostname()   
    IPAddr=socket.gethostbyname(hostname)
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=logging.DEBUG)
    logging.info(f"GitHub Webhook Listener Version: {__version__}")
    app.logger.setLevel(logging.DEBUG)
    app.run(host=IPAddr, port=8090, debug=True)