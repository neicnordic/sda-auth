FROM python:3.7-alpine

WORKDIR /sda-auth

COPY . ./

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev && \
    pip install -r requirements.txt && \
    python setup.py install && \
    apk del gcc musl-dev libffi-dev openssl-dev && \
    rm -rf /root/.cache

CMD ["python", "sda_auth/route.py"]
