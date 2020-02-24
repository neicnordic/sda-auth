# Production setup

## Build a Docker image

Using the provided Dockerfile, you may build a Docker image:

```bash
FROM python:3.7.6-slim

WORKDIR /sda-auth

COPY . ./

RUN apt update && \
    pip3 install -r backend/requirements.txt

CMD ["python3", "backend/route.py", "--settings_file", "/vault/secrets/credentials.yaml"]
```

```bash
docker build -t neicnordic/sda-auth:mytag <path-to-Dockerfile-folder>
```

Note that the settings file corresponds to the credentials provided by Vault, which live under `/vault/secrets/credentials.yaml` in our environment.

## Deployment configuration

Configure the following environment variables in the `auth-server.yaml` deployment manifesto:

Parameter | Description | Defined value
--------- | ----------- | -------
`LOG_LEVEL` | Log level | `DEBUG`
`ELIXIR_REDIRECT_URI` | Redirect URL for Elixir authentication | `/elixir/login`
`BIND_ADDRESS` | Binding address for the web server container | `0.0.0.0`
`PORT` | Port for the web server container | `8080`
`SERVER_NAME` | Qualified endpoint for the web server | `login.ega.nbis.se`
`URL_SCHEME` | URL scheme may be http or https | `https`
`DEVELOPMENT` | Development mode | `False`

And define the desired container image as follows:

```yaml
containers:
  - name: auth-server
    image: "neicnordic/sda-auth:mytag" 
```

Should you want to update the secrets retrieved from Vault, please change the following configuration:

```yaml
"vault.hashicorp.com/agent-inject-template-credentials.yaml": |
  {{  with secret "lega-secrets/auth_creds" }}
  elexir:
    id: {{  .Data.elexir_id }}
    secret: {{  .Data.elexir_secret }}
  ega:
    user: {{  .Data.ega_user }}
    pass: {{  .Data.user_pass }}
  {{  end }}
```

In order to deploy the service, you may run:

```bash
kubectl apply -n mynamespace -f auth-server.yaml
```
