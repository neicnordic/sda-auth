FROM python:3.9.0-alpine

WORKDIR /sda-auth

COPY . ./

RUN apk add --no-cache --virtual deps gcc musl-dev libffi-dev openssl-dev file make && \
    pip install -r requirements.txt && \
    python setup.py install && \
    apk del deps && \
    rm -rf /root/.cache

CMD ["python", "sda_auth/route.py"]
