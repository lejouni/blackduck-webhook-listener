'''
This webhook support following tools for status change events:
* GitHub Advance Security (GHAS)
    * Black Duck SCA
    * Coverity SAST
* Security Risk Manager (SRM) v2024.9.3 ->
    * Black Duck SCA
    * Coverity SAST

'''
import sys
from flask import Flask, request,  abort
import socket
import logging
from timeit import default_timer as timer
import logging
import sys
import json
from remediators.blackduckRemediateVuln import BlackDuckRemediator
from remediators.coverityRemediateVuln import CoverityRemediator
from parsers.gitHubParser import GitHubParser
from parsers.srmParser import SRMParser
from utils.Constants import Tools

__version__="0.0.7"
__author__ = "Jouni Lehto"

app = Flask(__name__)

@app.route('/webhook/github', methods=['POST'])
def github_webhook():
    try:
        start = timer()
        success = False
        remediation_event = request.json
        metadata = GitHubParser().parseMetadata(remediation_event)
        if remediation_event["action"] == "closed_by_user" or remediation_event["action"] == "reopened_by_user":
            logging.debug(f'request.json: {json.dumps(remediation_event, indent=3)}')
            if metadata["tool"] == Tools.BLACK_DUCK:
                success = BlackDuckRemediator().updateStatus(metadata)
            elif metadata["tool"] == Tools.COVERITY or metadata["tool"] == Tools.CNC:
                success = CoverityRemediator().updateStatus(metadata)
            else:
                success = False
                logging.info(f'Tool {metadata["tool"]} is not implemented yet!')
        else:
            logging.error(f'Trigger: {remediation_event["action"]} is not currently supported!') 
            abort(400, f'Trigger: {remediation_event["action"]} is not currently supported!')   
        end = timer()
        usedTime = end - start
        logging.debug(f"Took: {usedTime} seconds.")
        if not success:
            abort(400, "Remediation failed!")
        else:
            return json.dumps({'success':True}), 200, {'ContentType':'application/json'}
    except Exception as e:
        logging.exception(e)            
        abort(400, e)

@app.route('/webhook/srm', methods=['POST'])
def srm_webhook():
    try:
        start = timer()
        success = False
        remediation_event = request.json
        if remediation_event["trigger"] == "finding:status-update" and remediation_event["reasons"][0]["reason"] == "user-action" and remediation_event["reasons"][0]["action"] == "triage status update":
            logging.debug(f'request.json: {json.dumps(remediation_event, indent=3)}')
            for finding in remediation_event["findings"]:
                for result in finding["results"]:
                    if not finding["findingStatus"]["id"] == "gone":
                        metadata = SRMParser().parseMetadata(result, finding, remediation_event)
                        if metadata["tool"]  == Tools.BLACK_DUCK:
                            success = BlackDuckRemediator().updateStatus(metadata)
                        elif metadata["tool"]  == Tools.COVERITY:
                            success = CoverityRemediator().updateStatus(metadata)
                        else:
                            logging.error(f'Tool: {metadata["tool"]} is not currently supported!')
                    else:
                        logging.error(f'Finding status: {finding["findingStatus"]["id"]} is not currently supported!')
        end = timer()
        usedTime = end - start
        logging.debug(f"Took: {usedTime} seconds.")
        if not success:
            abort(400, "Remediation failed!")
        else:
            return json.dumps({'success':True}), 200, {'ContentType':'application/json'}
    except Exception as e:
        logging.exception(e)            
        abort(400, e)

if __name__ == '__main__':
    hostname=socket.gethostname()   
    IPAddr=socket.gethostbyname(hostname)
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=logging.DEBUG)
    logging.info(f"Black Duck Webhook Listener Version: {__version__}")
    app.logger.setLevel(logging.DEBUG)
    app.run(host=IPAddr, port=8090, debug=True)