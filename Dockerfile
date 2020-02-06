FROM python:3.7.2-slim

WORKDIR /elixir-auth

COPY . ./

RUN apt update && \
    pip3 install -r backend/requirements.txt

CMD ["python3", "backend/app.py"]
