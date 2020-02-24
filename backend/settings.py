import os
import sys
import yaml
import logging


# YAML file settings

ARG = "--settings_file"
SETTINGS_FILE = "settings-sample.yaml"

if ARG in sys.argv:
    try:
        SETTINGS_FILE = sys.argv[sys.argv.index(ARG)+1]
    except IndexError:
        logging.error("No argument for --settings_file")
        sys.exit(1)

try:
    current_dir = os.path.dirname(os.path.realpath(__file__))
    yaml_settings_fh = open(os.path.join(current_dir, SETTINGS_FILE))
except FileNotFoundError:
    parent_dir = os.path.join(current_dir, os.pardir)
    yaml_settings_fh = open(os.path.join(parent_dir, SETTINGS_FILE))

yaml_settings = yaml.safe_load(yaml_settings_fh)
yaml_settings_fh.close()

SERVICE_SETTINGS = { "LOG_LEVEL" :  yaml_settings.get("logLevel", "DEBUG"),
                     "ELIXIR_REDIRECT_URI" : yaml_settings.get("elixir", {}).get("redirectUri", "/elixir/login"),
                     "ELIXIR_ID" : yaml_settings.get("elixir", {}).get("id", "XC56EL11xx"),
                     "ELIXIR_SECRET" : yaml_settings.get("elixir", {}).get("secret", "wHPVQaYXmdDHg"),
                     "BIND_ADDRESS" : yaml_settings.get("bindAddress", "localhost"),
                     "PORT" : yaml_settings.get("port", 31111),
                     "SERVER_NAME" : yaml_settings.get("serverName", "localhost:31111"),
                     "URL_SCHEME" : yaml_settings.get("urlScheme", "http"),
                     "DEVELOPMENT" : yaml_settings.get("development", True),
                     "SECRET_KEY" : yaml_settings.get("secretKey", "de8b3fe55c7d9fb32de24b8428470876f00021f88c9eb7ff"),
                     "CERT_FILE" : yaml_settings.get("certFile", ""),
                     "KEY_FILE" : yaml_settings.get("keyFile", ""),
                     "CA_CERTS" :  yaml_settings.get("caCerts", "") }

# ENV settings

def overwrite_with_env(env_var):
    if env_var in os.environ:
        SERVICE_SETTINGS[env_var] = os.environ.get(env_var)

for var in SERVICE_SETTINGS.keys():
    overwrite_with_env(var)