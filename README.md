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
`ELIXIR_SCOPE` | Additional OIDC scope | `ga4gh_passport_v1 profile email`
`ELIXIR_JWTPRIVATEKEY` | Path to private key for signing the JWT token | `keys/sign-rsa-jwt.key`
`ELIXIR_JWTSIGNATUREALG` | Algorithm used to sign the JWT token. ES256 (ECDSA) or RS256 (RSA) are supported | `RS256`
`CEGA_AUTHURL` | CEGA server endpoint | `http://cega:8443/lega/v1/legas/users/`
`CEGA_ID` | CEGA server authentication id | `dummy`
`CEGA_SECRET` | CEGA server authentication secret | `dummy`
`CEGA_JWTPRIVATEKEY` | Path to private key for signing the JWT token | `keys/sign-jwt.key`
`CEGA_JWTSIGNATUREALG` | Algorithm used to sign the JWT token. ES256 (ECDSA) or RS256 (RSA) are supported | `ES256`
`CEGA_JWTISSUER` | Issuer of CEGA JWT tokens | `http://auth:8080`
`SERVER_CERT` | Certificate file path | `""`
`SERVER_KEY` | Private key file path | `""`
`S3INBOX` | S3 inbox host | `s3.example.com`

## Running the development setup

First, create a RSA private key under the name `sign-rsa-jwt.key` in the folder `keys`.

Start the full stack  bu running docker-compose in the dev-server folder:

```bash
docker-compose up -d --force-recreate --build
```

## Building a Docker container

Using the provided Dockerfile, you may build a Docker image:

```bash
docker build -t neicnordic/sda-auth:mytag <path-to-Dockerfile-folder>
```
