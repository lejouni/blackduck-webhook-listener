'''
This is a webhook for the GitHub Advance Security status change events to update finding statuses also in 
Black Duck tools.

This will require that Sarif format findings are created via black-duck-sarif-formatter (https://github.com/synopsys-sig-community/blackduck-sarif-formatter).
Requirements per tool:
    Black Duck: the repository name (github.repository) is used for project name and branch name (github.ref_name) for project version.
'''
import sys
from flask import Flask, request,  abort
import socket
import logging
from timeit import default_timer as timer
import logging
import sys
import json
from blackduckRemediateVuln import BlackDuckRemediator

__version__="0.0.3"
__author__ = "Jouni Lehto"

app = Flask(__name__)
bd_url="https://testing.blackduck.synopsys.com"
bd_access_token="ZGNjNzRmMGYtM2I2Yi00Y2U1LWI1ZGUtYTNhYmI5MzYwNzc2Ojg3NWNjMDczLWYyN2QtNGI4MS04ZjZlLTUzMzk1NDNjNzQ1NA=="

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
                    #NOTE Black will need black duck projectName, projectVersionName, componentName, componentVersionName, vulnerabilityName, remediationStatus, remediationComment, dismissedBy
                    success = remediator.remediate(projectName, projectVersionName, rule_id[1],rule_id[2],rule_id[0],remediation_event["sender"]["login"], remediation_event["alert"]["dismissed_reason"], remediation_event["alert"]["dismissed_comment"])
                elif str(remediation_event["alert"]["rule"]["id"]).startswith("POLICY"):
                    #NOTE projectName, projectVersionName, componentName, componentVersionName, approvalStatus, comment="-", overrideExpiresAt=None, dismissedBy
                    success = remediator.updatePolicyStatus(projectName, projectVersionName, rule_id[2], rule_id[3], rule_id[1], 
                                                            f'{"IN_VIOLATION_OVERRIDDEN" if remediation_event["action"] == "closed_by_user" else "IN_VIOLATION"}',
                                                            remediation_event["sender"]["login"], remediation_event["alert"]["dismissed_reason"],remediation_event["alert"]["dismissed_comment"])
                elif str(remediation_event["alert"]["rule"]["id"]).startswith("IAC"):
                    #NOTE help_uri contains the whole path to iac finding
                    success = remediator.dismissIaC(remediation_event["alert"]["rule"]["help_uri"], 
                                                    f'{True if remediation_event["action"] == "closed_by_user" else False}')
            else:
                success = False
                logging.error(f'Tool {remediation_event["alert"]["tool"]["name"]} is not implemented yet!')
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