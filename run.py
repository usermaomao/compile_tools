#!/usr/bin/env python3
"""
Compile Tools - Launcher Script
===============================

This script provides a convenient way to launch the Compile Tools application
with proper error handling and environment checks.
"""

import sys
import os
import subprocess

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import PySide6
        import paramiko
        print("✓ All dependencies are installed")
        return True
    except ImportError as e:
        print(f"✗ Missing dependency: {e}")
        print("Please install dependencies with: pip install -r requirements.txt")
        return False

def main():
    """Main launcher function"""
    print("Compile Tools - Remote Compilation Manager")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists("main.py"):
        print("✗ main.py not found. Please run this script from the project directory.")
        sys.exit(1)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Initialize database
    try:
        import database
        database.create_tables()
        print("✓ Database initialized")
    except Exception as e:
        print(f"✗ Database initialization failed: {e}")
        sys.exit(1)
    
    # Launch the application
    try:
        print("🚀 Launching Compile Tools...")
        import main
        # The main.py script will handle the rest
    except KeyboardInterrupt:
        print("\n👋 Application closed by user")
    except Exception as e:
        print(f"✗ Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
