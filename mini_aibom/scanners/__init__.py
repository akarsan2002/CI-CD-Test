# Importing each module runs its class definition, which triggers
# auto-registration in base.py. To add a scanner: create the file, import it here.
from . import (  # noqa: F401
    dependency_scanner, code_scanner, model_file_scanner, mcp_config_scanner, n8n_scanner,
    log_scanner,
)
