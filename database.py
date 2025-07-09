"""
Compile Tools - Database Module
-------------------------------

This module handles all database interactions for the Compile Tools application.
It uses SQLite to store SSH host configurations and compile project configurations.

Functions:
    get_db_connection: Establishes a connection to the SQLite database.
    create_tables: Creates necessary tables if they don't exist.
    add_ssh_host, get_all_ssh_hosts, get_ssh_host_by_id,
    update_ssh_host, delete_ssh_host: CRUD operations for SSH hosts.
    add_compile_project, get_all_compile_projects, get_compile_project_by_id,
    update_compile_project, delete_compile_project: CRUD operations for compile projects.

The database file is stored in a standard user-specific data directory.
"""
import sqlite3
from typing import List, Optional, Tuple, Any
import os
import sys # Needed for sys.platform
from pathlib import Path

# Determine OS-specific path for the database
APP_NAME = "CompileTools"
if os.name == 'nt':  # Windows
    DB_DIR = Path(os.getenv('APPDATA', Path.home() / "AppData" / "Roaming")) / APP_NAME
elif sys.platform == "darwin":  # macOS
    DB_DIR = Path.home() / "Library" / "Application Support" / APP_NAME
else:  # Linux and other POSIX
    DB_DIR = Path(os.getenv('XDG_DATA_HOME', Path.home() / ".local" / "share")) / APP_NAME

DB_DIR.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
DB_NAME = DB_DIR / "compile_tools.db"
# print(f"Database will be stored at: {DB_NAME}") # For debugging path

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(str(DB_NAME)) # Use str() for Path object
    conn.row_factory = sqlite3.Row # Access columns by name
    return conn

def create_tables():
    """Creates the necessary tables if they don't already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # SSH Hosts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ssh_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            hostname TEXT NOT NULL,
            port INTEGER DEFAULT 22,
            username TEXT NOT NULL,
            auth_method TEXT NOT NULL CHECK(auth_method IN ('password', 'key')),
            password TEXT,
            key_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Note: Storing passwords directly is not secure for production systems.
    # For a real application, consider using system keychain services or encryption.
    # For this project, we'll store it directly as per typical simplified tool requirements.

    # Compile Projects Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS compile_projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,       -- User-defined unique name for the project
            remote_base_path TEXT NOT NULL,  -- Base path of the project on the remote server
            compile_commands TEXT NOT NULL,  -- Multi-line commands to run for compilation
            artifact_path TEXT NOT NULL,     -- Path to the directory where artifacts are stored after compilation
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Renamed remote_path to remote_base_path for clarity
    # Renamed commands to compile_commands for clarity
    # Renamed artifact_dir to artifact_path for clarity

    conn.commit()
    conn.close()

# --- SSH Host CRUD Operations ---

def add_ssh_host(name: str, hostname: str, port: int, username: str,
                 auth_method: str, password: Optional[str] = None,
                 key_path: Optional[str] = None) -> Optional[int]:
    """Adds a new SSH host to the database. Returns the ID of the new host or None on failure."""
    if auth_method == "password" and password is None:
        raise ValueError("Password cannot be None for password authentication.")
    if auth_method == "key" and key_path is None:
        raise ValueError("Key path cannot be None for key authentication.")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO ssh_hosts (name, hostname, port, username, auth_method, password, key_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (name, hostname, port, username, auth_method, password, key_path))
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError: # Handles UNIQUE constraint violation for 'name'
        print(f"Error: SSH host with name '{name}' already exists.")
        return None
    except Exception as e:
        print(f"Database error: {e}")
        return None
    finally:
        conn.close()

def get_all_ssh_hosts() -> List[sqlite3.Row]:
    """Retrieves all SSH hosts from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, hostname, port, username, auth_method, key_path FROM ssh_hosts ORDER BY name")
    hosts = cursor.fetchall()
    conn.close()
    return hosts

def get_ssh_host_by_id(host_id: int) -> Optional[sqlite3.Row]:
    """Retrieves a specific SSH host by its ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ssh_hosts WHERE id = ?", (host_id,))
    host = cursor.fetchone()
    conn.close()
    return host

def get_ssh_host_by_name(name: str) -> Optional[sqlite3.Row]:
    """Retrieves a specific SSH host by its name."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ssh_hosts WHERE name = ?", (name,))
    host = cursor.fetchone()
    conn.close()
    return host

def update_ssh_host(host_id: int, name: str, hostname: str, port: int, username: str,
                    auth_method: str, password: Optional[str] = None,
                    key_path: Optional[str] = None) -> bool:
    """Updates an existing SSH host. Returns True on success, False on failure."""
    if auth_method == "password" and password is None:
        raise ValueError("Password cannot be None for password authentication.")
    if auth_method == "key" and key_path is None:
        raise ValueError("Key path cannot be None for key authentication.")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE ssh_hosts
            SET name = ?, hostname = ?, port = ?, username = ?,
                auth_method = ?, password = ?, key_path = ?
            WHERE id = ?
        """, (name, hostname, port, username, auth_method, password, key_path, host_id))
        conn.commit()
        return cursor.rowcount > 0 # Check if any row was updated
    except sqlite3.IntegrityError:
        print(f"Error: SSH host with name '{name}' might already exist elsewhere.")
        return False
    except Exception as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()

def delete_ssh_host(host_id: int) -> bool:
    """Deletes an SSH host by its ID. Returns True on success, False on failure."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM ssh_hosts WHERE id = ?", (host_id,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    # Initialize database and tables when script is run directly (for setup)
    print("Initializing database and creating tables if they don't exist...")
    create_tables()
    print("Database setup complete.")

    # Example Usage (Optional: for testing)
    # print("\nAttempting to add a sample host...")
    # new_id = add_ssh_host("My Test Server", "test.example.com", 22, "testuser", "password", "testpass")
    # if new_id:
    #     print(f"Added host with ID: {new_id}")
    # else:
    #     print("Failed to add host or host already exists.")

    # print("\nAll SSH Hosts:")
    # hosts = get_all_ssh_hosts()
    # if hosts:
    #     for host in hosts:
    #         print(f"  ID: {host['id']}, Name: {host['name']}, Hostname: {host['hostname']}, User: {host['username']}, Auth: {host['auth_method']}")
    # else:
    #     print("  No hosts found.")

    # if hosts:
    #     test_host_id = hosts[0]['id']
    #     print(f"\nDetails for host ID {test_host_id}:")
    #     host_detail = get_ssh_host_by_id(test_host_id)
    #     if host_detail:
    #         print(f"  Name: {host_detail['name']}, Key Path: {host_detail['key_path']}")

        # print(f"\nAttempting to update host ID {test_host_id}...")
        # success = update_ssh_host(test_host_id, host_detail['name'] + " (Updated)", host_detail['hostname'],
        #                           host_detail['port'], "newuser", "key", key_path="/path/to/new_id_rsa")
        # print(f"Update successful: {success}")

        # print("\nAll SSH Hosts after update:")
        # for host in get_all_ssh_hosts():
        #     print(f"  ID: {host['id']}, Name: {host['name']}, User: {host['username']}")

        # print(f"\nAttempting to delete host ID {test_host_id}...")
        # success = delete_ssh_host(test_host_id)
        # print(f"Deletion successful: {success}")

        # print("\nAll SSH Hosts after deletion:")
        # for host in get_all_ssh_hosts():
        #     print(f"  ID: {host['id']}, Name: {host['name']}")

    # print("\nAttempting to add a host with key auth...")
    # key_host_id = add_ssh_host("Key Auth Server", "key.example.com", 2222, "keyuser", "key", key_path="~/.ssh/id_rsa")
    # if key_host_id:
    #     print(f"Added key auth host with ID: {key_host_id}")
    #     key_host_details = get_ssh_host_by_id(key_host_id)
    #     print(f"  Retrieved Key Path: {key_host_details['key_path']}")
    #     # delete_ssh_host(key_host_id) # Clean up
    # else:
    #     print("Failed to add key auth host.")

# --- Compile Project CRUD Operations ---

def add_compile_project(name: str, remote_base_path: str, compile_commands: str, artifact_path: str) -> Optional[int]:
    """Adds a new compile project to the database. Returns the ID of the new project or None on failure."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO compile_projects (name, remote_base_path, compile_commands, artifact_path)
            VALUES (?, ?, ?, ?)
        """, (name, remote_base_path, compile_commands, artifact_path))
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        print(f"Error: Compile project with name '{name}' already exists.")
        return None
    except Exception as e:
        print(f"Database error: {e}")
        return None
    finally:
        conn.close()

def get_all_compile_projects() -> List[sqlite3.Row]:
    """Retrieves all compile projects from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, remote_base_path, compile_commands, artifact_path FROM compile_projects ORDER BY name")
    projects = cursor.fetchall()
    conn.close()
    return projects

def get_compile_project_by_id(project_id: int) -> Optional[sqlite3.Row]:
    """Retrieves a specific compile project by its ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM compile_projects WHERE id = ?", (project_id,))
    project = cursor.fetchone()
    conn.close()
    return project

def update_compile_project(project_id: int, name: str, remote_base_path: str,
                           compile_commands: str, artifact_path: str) -> bool:
    """Updates an existing compile project. Returns True on success, False on failure."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE compile_projects
            SET name = ?, remote_base_path = ?, compile_commands = ?, artifact_path = ?
            WHERE id = ?
        """, (name, remote_base_path, compile_commands, artifact_path, project_id))
        conn.commit()
        return cursor.rowcount > 0
    except sqlite3.IntegrityError:
        print(f"Error: Compile project with name '{name}' might already exist elsewhere.")
        return False
    except Exception as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()

def delete_compile_project(project_id: int) -> bool:
    """Deletes a compile project by its ID. Returns True on success, False on failure."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM compile_projects WHERE id = ?", (project_id,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()
