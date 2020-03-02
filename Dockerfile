FROM python:3.7.6-slim-stretch

WORKDIR /sda-auth

COPY . ./

RUN apt update && \
    pip3 install -r backend/requirements.txt

CMD ["python3", "backend/route.py"]
