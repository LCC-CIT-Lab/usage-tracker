import os
import toml

def load_config():
    # Load configurations
    root_path = os.path.dirname(os.path.abspath(__file__))  # Adjust to your package structure
    config_path = os.path.join(root_path, '../config.toml')  # Adjust the path to where your config.toml is located
    if os.path.exists(config_path):
        return toml.load(config_path)  # Return the loaded configuration data
    else:
        raise FileNotFoundError("The configuration file was not found.")
