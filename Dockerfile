FROM public.ecr.aws/docker/library/python:3.13.0b2-alpine3.20 as install
LABEL NAME="GitHub Webhook Listener"
LABEL VERSION=0.0.1

WORKDIR /
RUN mkdir -m 777 -p github
RUN python -m pip install --upgrade pip 
RUN pip install pipenv
COPY requirements.txt /github/
RUN pip install -r /github/requirements.txt
COPY app.py /github/
COPY blackduckRemediateVuln.py /github/
EXPOSE 8090/tcp
WORKDIR /github
# These are needed for Seeker agent installation
# RUN apk add build-base linux-headers
# RUN pip install --trusted-host demo.seeker.synopsys.com:443 --extra-index-url "https://demo.seeker.synopsys.com/pypi-server/simple" seeker-agent
# ENTRYPOINT ["seeker-exec", "python", "app.py"]
ENTRYPOINT ["python", "app.py"]