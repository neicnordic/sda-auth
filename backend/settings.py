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

SERVICE_SETTINGS = { "LOG_LEVEL" :  yaml_settings["logLevel"],
                     "ELIXIR_REDIRECT_URI" : yaml_settings["elixir"]["redirectUri"],
                     "ELIXIR_ID" : yaml_settings["elixir"]["id"],
                     "ELIXIR_SECRET" : yaml_settings["elixir"]["secret"],
                     "BIND_ADDRESS" : yaml_settings["bindAddress"],
                     "PORT" : yaml_settings["port"] }

# ENV settings

def overwrite_with_env(env_var):
    if env_var in os.environ:
        SERVICE_SETTINGS[env_var] = os.environ.get(env_var)

for var in SERVICE_SETTINGS.keys():
    overwrite_with_env(var)