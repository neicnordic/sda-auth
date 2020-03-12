# SDA authentication service

This service allows users to log in both via Elixir AAI or EGA.

## Configuration

The following settings can be configured for deploying the service, either by using environment variables or a YAML file.

Parameter | Description | Defined value
--------- | ----------- | -------
`LOG_LEVEL` | Log level | `DEBUG`
`CONF_FILE_PATH` | Settings file path | `settings-sample.yaml`
`ELIXIR_REDIRECT_URI` | Redirect URL for Elixir authentication | `/elixir/login`
`ELIXIR_ID` | Elixir authentication id | `XC56EL11xx`
`ELIXIR_SECRET` | Elixir authentication secret | `wHPVQaYXmdDHg`
`ELIXIR_AUTH_URL` | Elixir authentication endpoint | `http://localhost:9090/auth`
`ELIXIR_TOKEN_URL` | Elixir token endpoint | `http://localhost:9090/token`
`ELIXIR_CERTS_URL` | Elixir certificates endpoint | `http://localhost:9090/certs`
`ELIXIR_USERINFO_URL` | Elixir user info endpoint | `http://localhost:9090/me`
`ELIXIR_ISSUER_URL` | Elixir issuer URL | `http://localhost:9090`
`ELIXIR_REVOCATION_URL` | Elixir token revocation endpoint | `http://localhost:9090`
`CEGA_AUTH_URL` | CEGA server endpoint | `http://localhost:8443/lega/v1/legas/users/`
`CEGA_ID` | CEGA server authentication id | `dummy`
`CEGA_SECRET` | CEGA server authentication secret | `dummy`
`JWT_PRIVATE_KEY` | Path to private key for signing the JWT token | `keys/sign-jwt.key`
`JWT_SIGNATURE_ALG` | Algorithm used to sign the JWT token. ES and EC are common choices | `ES256`
`BIND_ADDRESS` | Binding address for the web server container | `0.0.0.0`
`PORT` | Port for the web server container | `31111`
`SERVER_NAME` | Qualified endpoint for the web server | `localhost:31111`
`URL_SCHEME` | URL scheme may be http or https | `http`
`SECRET_KEY` | Secret hash used to protect user sessions | `"de8b3fe55c7d9fb32de24b8428470876f00021f88c9eb7ff"`
`CERT_FILE` | Certificate file path | `""`
`KEY_FILE` | Private key file path | `""`
`CA_CERTS` | (Root) CA certificate file path | `""`

## Running the development setup

Start the mock services located under the mock-server folder:

```bash
docker-compose up -d --force-recreate
```

And to start the backend, you may run:

```bash
pip3 install -r requirements.txt
python3 backend/route.py
```

## Building a Docker container

Using the provided Dockerfile, you may build a Docker image:

```bash
docker build -t neicnordic/sda-auth:mytag <path-to-Dockerfile-folder>
```
