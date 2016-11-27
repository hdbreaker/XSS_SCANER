FROM python:2
ADD *.py /tmp/
ADD requirements.txt /tmp/
RUN pip install -r /tmp/requirements.txt
ENTRYPOINT ["python", "/tmp/xss_scanner.py"]
