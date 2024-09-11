'''
This is a webhook for the GitHub Advance Security (GHAS) status change events to update finding statuses also in 
Black Duck tools.

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

__version__="0.0.4"
__author__ = "Jouni Lehto"

app = Flask(__name__)

@app.route('/webhook/github/asevents', methods=['POST'])
def webhook():
    try:
        start = timer()
        success = False
        remediation_event = request.json
        if remediation_event["action"] == "closed_by_user" or remediation_event["action"] == "reopened_by_user":
            if remediation_event["alert"]["tool"]["name"] == "Synopsys Black Duck Intelligent":
                logging.debug(f'request.json: {json.dumps(request.json, indent=3)}')
                success = BlackDuckRemediator().handleEvent(remediation_event)
            else:
                success = False
                logging.info(f'Tool {remediation_event["alert"]["tool"]["name"]} is not implemented yet!')
            end = timer()
            usedTime = end - start
            logging.debug(f"Took: {usedTime} seconds.")
            if not success:
                abort(400, "Remediation failed!")
            else:
                return json.dumps({'success':True}), 200, {'ContentType':'application/json'}
        else:
            logging.error(f'Trigger: {remediation_event["action"]} is not currently supported!') 
            abort(400, f'Trigger: {remediation_event["action"]} is not currently supported!')   
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