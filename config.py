"""
Compile Tools - Configuration Module
====================================

This module contains configuration settings for the Compile Tools application.
"""

import os
from pathlib import Path

# Application Information
APP_NAME = "Compile Tools"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Remote Compilation and File Management Tool"

# UI Configuration
UI_THEME = {
    "primary_color": "#007AFF",
    "secondary_color": "#5856D6", 
    "success_color": "#34C759",
    "warning_color": "#FF9500",
    "error_color": "#FF3B30",
    "background_color": "#F2F2F7",
    "text_color": "#000000",
    "border_color": "#C7C7CC"
}

# Window Settings
WINDOW_DEFAULT_SIZE = (1000, 700)
WINDOW_MIN_SIZE = (800, 600)

# Connection Settings
SSH_CONNECTION_TIMEOUT = 10  # seconds
SSH_STATUS_UPDATE_INTERVAL = 5000  # milliseconds
MAX_LOG_LINES = 1000  # Maximum lines in compile log

# File Transfer Settings
DOWNLOAD_CHUNK_SIZE = 8192  # bytes
MAX_CONCURRENT_DOWNLOADS = 3

# Database Settings
DATABASE_NAME = "compile_tools.db"

# Logging Settings
LOG_LEVEL = "INFO"
LOG_FILE = "compile_tools.log"
MAX_LOG_FILE_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 3

# Security Settings
AUTO_ACCEPT_HOST_KEYS = True  # For development convenience
SESSION_TIMEOUT = 3600  # seconds (1 hour)

# Feature Flags
FEATURES = {
    "auto_refresh_artifacts": True,
    "connection_status_monitoring": True,
    "download_progress_dialog": True,
    "compilation_interruption": True,
    "ssh_connection_pooling": True
}

# Default Values
DEFAULTS = {
    "ssh_port": 22,
    "auth_method": "password",
    "compile_timeout": 300,  # 5 minutes
    "artifact_refresh_after_compile": True
}

def get_app_data_dir():
    """Get the application data directory based on the operating system"""
    if os.name == 'nt':  # Windows
        return Path(os.getenv('APPDATA', Path.home() / "AppData" / "Roaming")) / APP_NAME
    elif os.sys.platform == "darwin":  # macOS
        return Path.home() / "Library" / "Application Support" / APP_NAME
    else:  # Linux and other POSIX
        return Path(os.getenv('XDG_DATA_HOME', Path.home() / ".local" / "share")) / APP_NAME

def get_database_path():
    """Get the full path to the database file"""
    return get_app_data_dir() / DATABASE_NAME

def get_log_file_path():
    """Get the full path to the log file"""
    return get_app_data_dir() / LOG_FILE

# Ensure app data directory exists
APP_DATA_DIR = get_app_data_dir()
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
