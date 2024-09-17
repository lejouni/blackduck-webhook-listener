FROM public.ecr.aws/docker/library/python:3.13.0b2-alpine3.20 as install
LABEL NAME="BlackDuck Webhook Listener"
LABEL VERSION=0.0.5

WORKDIR /
RUN mkdir -m 777 -p webhook
RUN mkdir -m 777 -p webhook/parsers
RUN mkdir -m 777 -p webhook/remediators
RUN mkdir -m 777 -p webhook/utils
RUN python -m pip install --upgrade pip 
RUN pip install pipenv
COPY requirements.txt /webhook/
RUN pip install -r /webhook/requirements.txt
COPY parsers/*.py /webhook/parsers
COPY remediators/*.py /webhook/remediators
COPY utils/*.py /webhook/utils
COPY BlackDuckWebhook.py /webhook/
COPY LICENSE /webhook/
EXPOSE 8090/tcp
WORKDIR /webhook
# These are needed for Seeker agent installation
# RUN apk add build-base linux-headers
# RUN pip install --trusted-host demo.seeker.synopsys.com:443 --extra-index-url "https://demo.seeker.synopsys.com/pypi-server/simple" seeker-agent
# ENTRYPOINT ["seeker-exec", "python", "BlackDuckWebhook.py"]
ENTRYPOINT ["python", "BlackDuckWebhook.py"]