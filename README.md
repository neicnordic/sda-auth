# SDA authentication service

This service allows users to log in both via Elixir AAI or EGA.

## Configuration

The following settings can be configured for deploying the service, either by using environment variables or a YAML file.

Parameter | Description | Defined value
--------- | ----------- | -------
`LOG_LEVEL` | Log level | `info`
`ELIXIR_ID` | Elixir authentication id | `XC56EL11xx`
`ELIXIR_SECRET` | Elixir authentication secret | `wHPVQaYXmdDHg`
`ELIXIR_ISSUER` | Elixir issuer URL | `http://oidc:9090`
`ELIXIR_JWTPRIVATEKEY` | Path to private key for signing the JWT token | `keys/sign-rsa-jwt.key`
`ELIXIR_JWTSIGNATUREALG` | Algorithm used to sign the JWT token. ES256 (ECDSA) or RS256 (RSA) are supported | `RS256`
`CEGA_AUTHURL` | CEGA server endpoint | `http://cega:8443/lega/v1/legas/users/`
`CEGA_ID` | CEGA server authentication id | `dummy`
`CEGA_SECRET` | CEGA server authentication secret | `dummy`
`CEGA_JWTPRIVATEKEY` | Path to private key for signing the JWT token | `keys/sign-jwt.key`
`CEGA_JWTSIGNATUREALG` | Algorithm used to sign the JWT token. ES256 (ECDSA) or RS256 (RSA) are supported | `ES256`
`CEGA_JWTISSUER` | Issuer of CEGA JWT tokens | `http://auth:8080`
`CORS_ORIGINS` | Allowed Cross-Origin Resource Sharing (CORS) origins | `""`
`CORS_METHODS` | Allowed Cross-Origin Resource Sharing (CORS) methods | `""`
`CORS_CREDENTIALS` | If cookies, authorization headers, and TLS client certificates are allowed over CORS | `false`
`SERVER_CERT` | Certificate file path | `""`
`SERVER_KEY` | Private key file path | `""`
`S3INBOX` | S3 inbox host | `s3.example.com`

## Running the development setup

First, create a RSA private key under the name `sign-rsa-jwt.key` in the folder `keys`.
```
openssl genrsa -out keys/sign-rsa-jwt.key 2048  && chmod 664 keys/sign-rsa-jwt.key
```

Start the full stack by running docker-compose in the `dev-server` folder:

```bash
docker-compose up --build
```

The current setup also requires that
```
127.0.0.1  oidc
```
is added to `/etc/hosts`, so that routing works properly.

## Running with Cross-Origin Resource Sharing (CORS)

This service can be run as a backend only, and in the case where the frontend
is running somewhere else, CORS is needed.

Recommended cors settings for a given host are:
```
export CORS_ORIGINS="https://<frontend-url>"
export CORS_METHODS="GET,OPTIONS"
export CORS_CREDENTIALS="true"
```

There is a minimal CORS login testing site at http://localhost:8000 of the
dev-server. To use the CORS login page, the `dev-server/docker-compose.yml` file
must be updated by setting the `CLIENT_REDIRECT_URI` (under
`services/oidc/environment`) to `http://localhost:8000` and restart the server.

## Building a Docker container

Using the provided Dockerfile, you may build a Docker image:

```bash
docker build -t neicnordic/sda-auth:mytag <path-to-Dockerfile-folder>
```
