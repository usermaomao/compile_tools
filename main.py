"""
Compile Tools - Main Application
--------------------------------

This module contains the main application logic for the Compile Tools desktop application.
It includes the main window, all UI pages (Host Management, Project Configuration,
Compile & Run), dialogs for adding/editing configurations, and the core logic for
SSH interactions, remote compilation, and artifact management.

Classes:
    CompilationThread: Handles remote compilation in a separate thread.
    SshHostDialog: Dialog for adding/editing SSH host configurations.
    CompileProjectDialog: Dialog for adding/editing compile project configurations.
    MainWindow: The main application window orchestrating all UI and functionality.
"""
import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QStackedWidget, QLabel, QListWidgetItem, QPushButton,
    QDialog, QFormLayout, QLineEdit, QComboBox, QSpinBox, QFileDialog,
    QMessageBox, QCheckBox, QTextEdit
)
from PySide6.QtCore import Qt, QSize, QThread, Signal
from PySide6.QtWidgets import QGroupBox, QAbstractItemView # Added for artifact area
import database # Import database module
import paramiko # For SSH connection testing
import select # For non-blocking read from SSH channel
import os # For path joining in download
import stat # For checking file types (S_ISDIR)

# --- SSH Compilation Thread ---
class CompilationThread(QThread):
    log_received = Signal(str) # Signal to send log messages
    status_changed = Signal(str) # Signal for status updates (e.g., "Compiling", "Success", "Failed")
    compilation_finished = Signal(bool) # True for success, False for failure/interruption

    def __init__(self, ssh_client: paramiko.SSHClient, commands: str, remote_base_path: str, parent=None):
        super().__init__(parent)
        self.ssh_client = ssh_client
        self.commands = commands # Single string of commands, potentially multi-line
        self.remote_base_path = remote_base_path
        self._is_running = True
        self._channel = None

    def run(self):
        if not self.ssh_client or not self.ssh_client.get_transport() or \
           not self.ssh_client.get_transport().is_active():
            self.log_received.emit("SSH client is not connected or active.\n")
            self.status_changed.emit("Error: SSH Disconnected")
            self.compilation_finished.emit(False)
            return

        self._is_running = True
        self.status_changed.emit("Preparing compilation...")

        full_command = f"cd {self.remote_base_path} && {self.commands}"
        self.log_received.emit(f"Executing on remote: {full_command}\n\n")

        try:
            self._channel = self.ssh_client.get_transport().open_session()
            self._channel.set_combine_stderr(True) # Combine stdout and stderr

            # Execute the command
            # For PTY, useful for interactive sessions, but might not be needed for simple command execution
            # self._channel.get_pty()
            self._channel.exec_command(full_command)

            self.status_changed.emit("Compiling...")

            while self._is_running:
                # Non-blocking read using select
                ready_to_read, _, _ = select.select([self._channel], [], [], 0.1)
                if self._channel in ready_to_read:
                    if self._channel.recv_ready():
                        output = self._channel.recv(4096).decode('utf-8', errors='replace')
                        self.log_received.emit(output)
                    if self._channel.exit_status_ready() and not self._channel.recv_ready(): # Ensure all output is read
                        break # Command finished
                if not self._is_running: # Check again in case stop() was called
                    self.log_received.emit("\nCompilation was interrupted by user.\n")
                    self.status_changed.emit("Interrupted")
                    self.compilation_finished.emit(False)
                    if self._channel:
                        self._channel.close()
                    return

            exit_status = self._channel.recv_exit_status()

            # Read any remaining output after exit status is known
            while self._channel.recv_ready():
                 output = self._channel.recv(4096).decode('utf-8', errors='replace')
                 self.log_received.emit(output)

            if self._channel:
                self._channel.close()
            self._channel = None

            if exit_status == 0:
                self.log_received.emit(f"\nCompilation finished successfully (Exit Code: {exit_status}).\n")
                self.status_changed.emit("Compilation Successful")
                self.compilation_finished.emit(True)
            else:
                self.log_received.emit(f"\nCompilation failed (Exit Code: {exit_status}).\n")
                self.status_changed.emit(f"Compilation Failed (Code: {exit_status})")
                self.compilation_finished.emit(False)

        except Exception as e:
            error_msg = f"\nError during compilation: {str(e)}\n"
            self.log_received.emit(error_msg)
            self.status_changed.emit("Error")
            self.compilation_finished.emit(False)
        finally:
            if self._channel and not self._channel.closed:
                self._channel.close()
            self._channel = None
            self._is_running = False


    def stop(self):
        self.log_received.emit("Attempting to interrupt compilation...\n")
        self._is_running = False
        if self._channel:
            try:
                # Sending a Ctrl+C or similar signal can be complex and PTY-dependent.
                # For many non-interactive scripts, simply closing the channel or session
                # might be enough, or sending a specific signal if the remote process handles it.
                # If a PTY was allocated (self._channel.get_pty()), then:
                # self._channel.send('\x03') # Send Ctrl+C
                # For now, we rely on closing the channel and the loop condition.
                if not self._channel.closed:
                     self._channel.close() # This might be abrupt for the remote process
                self.log_received.emit("Interrupt signal sent (channel closed).\n")
            except Exception as e:
                self.log_received.emit(f"Error trying to stop/close channel: {e}\n")


class SshHostDialog(QDialog):
    def __init__(self, host_data=None, parent=None):
        super().__init__(parent)
        self.host_data = host_data # For editing existing host
        self.setWindowTitle("Add New SSH Host" if host_data is None else "Edit SSH Host")
        self.setMinimumWidth(450) # Increased width

        layout = QVBoxLayout(self)
        form_layout = QFormLayout()
        form_layout.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows) # Better for responsiveness
        form_layout.setLabelAlignment(Qt.AlignLeft) # Align labels to the left
        form_layout.setHorizontalSpacing(15)
        form_layout.setVerticalSpacing(10)


        self.name_edit = QLineEdit(host_data["name"] if host_data else "")
        self.name_edit.setPlaceholderText("e.g., My Web Server")
        form_layout.addRow("Display Name:", self.name_edit)

        self.hostname_edit = QLineEdit(host_data["hostname"] if host_data else "")
        self.hostname_edit.setPlaceholderText("e.g., server.example.com or IP")
        form_layout.addRow("Hostname/IP:", self.hostname_edit)

        self.port_spinbox = QSpinBox()
        self.port_spinbox.setRange(1, 65535)
        self.port_spinbox.setValue(host_data["port"] if host_data else 22)
        form_layout.addRow("Port:", self.port_spinbox)

        self.username_edit = QLineEdit(host_data["username"] if host_data else "")
        self.username_edit.setPlaceholderText("e.g., root, admin, user")
        form_layout.addRow("Username:", self.username_edit)

        self.auth_method_combo = QComboBox()
        self.auth_method_combo.addItems(["Password", "Key File"])
        form_layout.addRow("Auth Method:", self.auth_method_combo)

        # Password fields
        self.password_label = QLabel("Password:")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.show_password_checkbox = QCheckBox("Show Password")
        self.show_password_checkbox.toggled.connect(self.toggle_password_visibility)

        password_layout = QHBoxLayout()
        password_layout.addWidget(self.password_edit)
        password_layout.addWidget(self.show_password_checkbox)
        form_layout.addRow(self.password_label, password_layout)


        # Key file fields
        self.key_path_label = QLabel("Key File Path:")
        self.key_path_edit = QLineEdit(host_data["key_path"] if host_data and host_data.get("key_path") else "")
        self.key_path_edit.setPlaceholderText("Path to your private SSH key")
        self.key_browse_button = QPushButton("Browse...")
        self.key_browse_button.clicked.connect(self.browse_key_file)

        key_path_layout = QHBoxLayout()
        key_path_layout.addWidget(self.key_path_edit)
        key_path_layout.addWidget(self.key_browse_button)
        form_layout.addRow(self.key_path_label, key_path_layout)

        layout.addLayout(form_layout)

        # Buttons
        self.button_layout = QHBoxLayout()
        self.test_button = QPushButton("Test Connection")
        self.test_button.clicked.connect(self.test_ssh_connection)
        self.save_button = QPushButton("Save")
        self.save_button.setDefault(True) # Default button for Enter key
        self.save_button.clicked.connect(self.accept_dialog) # Use custom accept
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)

        self.button_layout.addStretch()
        self.button_layout.addWidget(self.test_button)
        self.button_layout.addWidget(self.save_button)
        self.button_layout.addWidget(self.cancel_button)
        layout.addLayout(self.button_layout)

        self.auth_method_combo.currentIndexChanged.connect(self.update_auth_fields_visibility)
        if host_data:
            auth_method = host_data.get("auth_method", "password")
            self.auth_method_combo.setCurrentText(auth_method.capitalize())
            if auth_method == "password":
                 self.password_edit.setText(host_data.get("password", "")) # Populate if editing
        else: # Default for new host
            self.auth_method_combo.setCurrentIndex(0)

        self.update_auth_fields_visibility(self.auth_method_combo.currentIndex())

        self.apply_styles()

    def apply_styles(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #f8f8f8; /* Light background for dialog */
            }
            QLineEdit, QSpinBox, QComboBox {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 14px;
            }
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
                border: 1px solid #007AFF; /* Highlight on focus */
            }
            QPushButton {
                min-width: 80px; /* Ensure buttons have a decent minimum width */
            }
        """)
        # Specific styles for browse button if needed
        self.key_browse_button.setStyleSheet("padding: 6px 10px; font-size: 13px;")


    def toggle_password_visibility(self, checked):
        if checked:
            self.password_edit.setEchoMode(QLineEdit.Normal)
        else:
            self.password_edit.setEchoMode(QLineEdit.Password)

    def update_auth_fields_visibility(self, index):
        # Index 0: Password, Index 1: Key File
        is_password_auth = (index == 0)
        self.password_label.setVisible(is_password_auth)
        self.password_edit.setVisible(is_password_auth)
        self.show_password_checkbox.setVisible(is_password_auth)

        self.key_path_label.setVisible(not is_password_auth)
        self.key_path_edit.setVisible(not is_password_auth)
        self.key_browse_button.setVisible(not is_password_auth)

    def browse_key_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select SSH Key File", "", "All Files (*);;PEM Files (*.pem)")
        if file_path:
            self.key_path_edit.setText(file_path)

    def get_data(self):
        auth_method_text = self.auth_method_combo.currentText().lower()
        data = {
            "name": self.name_edit.text().strip(),
            "hostname": self.hostname_edit.text().strip(),
            "port": self.port_spinbox.value(),
            "username": self.username_edit.text().strip(),
            "auth_method": auth_method_text,
            "password": self.password_edit.text() if auth_method_text == "password" else None,
            "key_path": self.key_path_edit.text().strip() if auth_method_text == "key" else None,
        }
        return data

    def accept_dialog(self):
        data = self.get_data()
        if not data["name"]:
            QMessageBox.warning(self, "Input Error", "Display Name cannot be empty.")
            self.name_edit.setFocus()
            return
        if not data["hostname"]:
            QMessageBox.warning(self, "Input Error", "Hostname/IP cannot be empty.")
            self.hostname_edit.setFocus()
            return
        if not data["username"]:
            QMessageBox.warning(self, "Input Error", "Username cannot be empty.")
            self.username_edit.setFocus()
            return

        if data["auth_method"] == "password" and not self.host_data: # Only require password if it's a new entry or password auth is selected
            # For editing, password can be empty if user doesn't want to change it
            # However, if they switch to password and it's empty, that's an issue.
            # This logic might need refinement based on how password updates are handled.
            # For now, let's assume if it's password auth, password field (even if empty for edit) is part of the data.
            pass # Password can be empty, it's up to the save logic to handle it.

        if data["auth_method"] == "key" and not data["key_path"]:
            QMessageBox.warning(self, "Input Error", "Key File Path cannot be empty for key authentication.")
            self.key_path_edit.setFocus()
            return

        self.accept() # Calls QDialog.accept()

    def test_ssh_connection(self):
        data = self.get_data()
        if not data["hostname"] or not data["username"]:
            QMessageBox.warning(self, "Connection Test Failed", "Hostname and Username are required to test connection.")
            return

        self.test_button.setEnabled(False)
        self.test_button.setText("Testing...")
        QApplication.processEvents() # Update UI

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Auto-accept host key

            if data["auth_method"] == "key":
                if not data["key_path"]:
                    QMessageBox.warning(self, "Connection Test Failed", "Key file path is required for key authentication.")
                    self.test_button.setEnabled(True)
                    self.test_button.setText("Test Connection")
                    return
                try:
                    ssh.connect(data["hostname"], port=data["port"], username=data["username"],
                                key_filename=data["key_path"], timeout=5)
                except paramiko.ssh_exception.PasswordRequiredException:
                     QMessageBox.critical(self, "Connection Test Failed",
                                         "SSH key is passphrase protected, and passphrase input is not yet supported. Or, the key is invalid.")
                     self.test_button.setEnabled(True)
                     self.test_button.setText("Test Connection")
                     return
            else: # Password authentication
                if data["password"] is None: # Should not happen due to get_data logic, but defensive
                    QMessageBox.warning(self, "Connection Test Failed", "Password is required for password authentication.")
                    self.test_button.setEnabled(True)
                    self.test_button.setText("Test Connection")
                    return
                ssh.connect(data["hostname"], port=data["port"], username=data["username"],
                            password=data["password"], timeout=5, allow_agent=False, look_for_keys=False)

            QMessageBox.information(self, "Connection Test Successful", "Successfully connected to the SSH server.")
            ssh.close()

        except paramiko.ssh_exception.AuthenticationException:
            QMessageBox.critical(self, "Connection Test Failed", "Authentication failed. Please check your credentials or key.")
        except paramiko.ssh_exception.NoValidConnectionsError:
            QMessageBox.critical(self, "Connection Test Failed", f"Unable to connect to port {data['port']} on {data['hostname']}.")
        except Exception as e:
            QMessageBox.critical(self, "Connection Test Failed", f"An error occurred: {str(e)}")
        finally:
            self.test_button.setEnabled(True)
            self.test_button.setText("Test Connection")

class CompileProjectDialog(QDialog):
    def __init__(self, project_data=None, parent=None):
        super().__init__(parent)
        self.project_data = project_data
        self.setWindowTitle("Add New Compile Project" if project_data is None else "Edit Compile Project")
        self.setMinimumWidth(500) # Wider dialog for more fields

        layout = QVBoxLayout(self)
        form_layout = QFormLayout()
        form_layout.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form_layout.setLabelAlignment(Qt.AlignLeft)
        form_layout.setHorizontalSpacing(15)
        form_layout.setVerticalSpacing(10)

        self.name_edit = QLineEdit(project_data["name"] if project_data else "")
        self.name_edit.setPlaceholderText("Unique name for this project configuration")
        form_layout.addRow("Project Name:", self.name_edit)

        self.remote_base_path_edit = QLineEdit(project_data["remote_base_path"] if project_data else "")
        self.remote_base_path_edit.setPlaceholderText("e.g., /home/user/my_project")
        form_layout.addRow("Remote Project Root Path:", self.remote_base_path_edit)

        self.compile_commands_edit = QTextEdit(project_data["compile_commands"] if project_data else "")
        self.compile_commands_edit.setPlaceholderText("Enter compile commands, one per line (e.g., make clean\nmake all)")
        self.compile_commands_edit.setMinimumHeight(100) # Good height for multiple lines
        form_layout.addRow("Compile Commands:", self.compile_commands_edit)

        self.artifact_path_edit = QLineEdit(project_data["artifact_path"] if project_data else "")
        self.artifact_path_edit.setPlaceholderText("e.g., /home/user/my_project/build/output")
        form_layout.addRow("Compiled Artifacts Path (Remote):", self.artifact_path_edit)

        layout.addLayout(form_layout)

        # Buttons
        self.button_layout = QHBoxLayout()
        self.save_button = QPushButton("Save")
        self.save_button.setDefault(True)
        self.save_button.clicked.connect(self.accept_dialog)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)

        self.button_layout.addStretch()
        self.button_layout.addWidget(self.save_button)
        self.button_layout.addWidget(self.cancel_button)
        layout.addLayout(self.button_layout)

        self.apply_styles()

    def apply_styles(self):
        # Inherit some styles from SshHostDialog or define new ones
        self.setStyleSheet("""
            QDialog { background-color: #f8f8f8; }
            QLineEdit, QTextEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 14px;
            }
            QLineEdit:focus, QTextEdit:focus {
                border: 1px solid #007AFF;
            }
            QPushButton { min-width: 80px; }
        """)
        self.compile_commands_edit.setStyleSheet("font-family: monospace;") # Monospace for commands

    def get_data(self):
        return {
            "name": self.name_edit.text().strip(),
            "remote_base_path": self.remote_base_path_edit.text().strip(),
            "compile_commands": self.compile_commands_edit.toPlainText().strip(), # Get plain text from QTextEdit
            "artifact_path": self.artifact_path_edit.text().strip(),
        }

    def accept_dialog(self):
        data = self.get_data()
        if not data["name"]:
            QMessageBox.warning(self, "Input Error", "Project Name cannot be empty.")
            self.name_edit.setFocus()
            return
        if not data["remote_base_path"]:
            QMessageBox.warning(self, "Input Error", "Remote Project Root Path cannot be empty.")
            self.remote_base_path_edit.setFocus()
            return
        if not data["compile_commands"]:
            QMessageBox.warning(self, "Input Error", "Compile Commands cannot be empty.")
            self.compile_commands_edit.setFocus()
            return
        if not data["artifact_path"]:
            QMessageBox.warning(self, "Input Error", "Compiled Artifacts Path cannot be empty.")
            self.artifact_path_edit.setFocus()
            return
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Compile Tools")
        self.setGeometry(100, 100, 800, 600)

        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0) # Remove margins for a more modern look
        main_layout.setSpacing(0) # Remove spacing between sidebar and content

        # Left Navigation Sidebar
        self.nav_bar = QListWidget()
        self.nav_bar.setFixedWidth(180) # Adjusted for a bit more space
        self.nav_bar.setStyleSheet("""
            QListWidget {
                background-color: #EFEFF4; /* iOS-like light gray */
                border: none;
                padding-top: 15px; /* Reduced top padding */
                outline: 0; /* Remove focus outline */
            }
            QListWidget::item {
                padding: 15px 20px; /* Adjusted padding for a taller feel */
                border-bottom: 1px solid #DCDCDC; /* Lighter separator */
                color: #333333; /* Darker text for better readability */
                font-size: 15px; /* Slightly larger font */
            }
            QListWidget::item:selected {
                background-color: #007AFF; /* iOS blue for selection */
                color: white; /* White text on selection */
                border-left: none; /* Remove left border, selection is full background */
                font-weight: 500; /* Slightly bolder font for selected item */
            }
            QListWidget::item:hover:!selected {
                background-color: #E5E5EA; /* Lighter gray for hover */
            }
        """)
        main_layout.addWidget(self.nav_bar)

        # Right Content Area
        self.content_stack = QStackedWidget()
        main_layout.addWidget(self.content_stack)

        # Populate Navigation and Content
        self.setup_navigation()

    def setup_navigation(self):
        # Host Management
        nav_hosts_item = QListWidgetItem("Host Management")
        # nav_hosts_item.setTextAlignment(Qt.AlignCenter) # Alignment handled by stylesheet padding
        self.nav_bar.addItem(nav_hosts_item)
        self.host_management_page = self.create_host_management_page()
        self.content_stack.addWidget(self.host_management_page)

        # Project Configuration
        nav_projects_item = QListWidgetItem("Project Configuration")
        # nav_projects_item.setTextAlignment(Qt.AlignCenter) # Alignment handled by stylesheet padding
        self.nav_bar.addItem(nav_projects_item)
        self.project_config_page = self.create_project_config_page() # Create the actual page
        self.content_stack.addWidget(self.project_config_page)

        # Compile Execution Page
        nav_compile_item = QListWidgetItem("Compile & Run")
        self.nav_bar.addItem(nav_compile_item)
        self.compile_execution_page = self.create_compile_execution_page()
        self.content_stack.addWidget(self.compile_execution_page)

        # Connect navigation clicks to content switching
        self.nav_bar.currentRowChanged.connect(self.content_stack.setCurrentIndex)

        # Select the first item by default
        if self.nav_bar.count() > 0:
            self.nav_bar.setCurrentRow(0)

        self.load_host_list()

    def create_host_management_page(self):
        page_widget = QWidget()
        layout = QVBoxLayout(page_widget)
        layout.setContentsMargins(20, 20, 20, 20) # Add some padding around the content
        layout.setSpacing(15) # Spacing between elements

        # Title
        title_label = QLabel("Host Management")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(title_label)

        # Host List
        self.host_list_widget = QListWidget()
        self.host_list_widget.setStyleSheet("""
            QListWidget {
                border: 1px solid #DCDCDC; /* Light border for the list widget itself */
                border-radius: 6px; /* Rounded corners for the list widget */
                outline: 0; /* No focus outline */
            }
            QListWidget::item {
                padding: 12px 15px; /* Padding within each item */
                border-bottom: 1px solid #EAEAEA; /* Separator line */
                background-color: white; /* Card-like background */
            }
            QListWidget::item:last-child { /* Remove border for the last item if possible via stylesheet */
                border-bottom: none;
            }
            QListWidget::item:selected {
                background-color: #007AFF;
                color: white;
                border-bottom: 1px solid #007AFF; /* Keep separator consistent or hide */
            }
            QListWidget::item:hover:!selected {
                background-color: #f7f7f7; /* Slight hover effect */
            }
        """)
        # Apply custom delegate later if more complex item structure is needed (e.g., status indicators within item)
        layout.addWidget(self.host_list_widget)

        # Action buttons layout
        action_buttons_layout = QHBoxLayout()

        self.add_host_button = QPushButton("Add New Host")
        self.add_host_button.setStyleSheet("padding: 8px 15px; font-size: 14px;")
        self.add_host_button = QPushButton("Add New Host")
        self.add_host_button.setStyleSheet("padding: 8px 15px; font-size: 14px;")
        self.add_host_button.clicked.connect(self.open_add_host_dialog)
        action_buttons_layout.addWidget(self.add_host_button)

        self.edit_host_button = QPushButton("Edit Selected")
        self.edit_host_button.setStyleSheet("padding: 8px 15px; font-size: 14px;")
        self.edit_host_button.setEnabled(False) # Disabled until a host is selected
        self.edit_host_button.clicked.connect(self.open_edit_host_dialog)
        action_buttons_layout.addWidget(self.edit_host_button)

        self.delete_host_button = QPushButton("Delete Selected")
        self.delete_host_button.setStyleSheet("padding: 8px 15px; font-size: 14px; background-color: #ffdddd; color: #D8000C;")
        self.delete_host_button.setEnabled(False) # Disabled until a host is selected
        self.delete_host_button.clicked.connect(self.delete_selected_host)
        action_buttons_layout.addWidget(self.delete_host_button)

        action_buttons_layout.addStretch() # Push buttons to the left

        layout.addLayout(action_buttons_layout)

        self.host_list_widget.itemSelectionChanged.connect(self.update_host_action_buttons_state)

        return page_widget

    def update_host_action_buttons_state(self):
        selected_items = self.host_list_widget.selectedItems()
        is_host_selected = len(selected_items) > 0

        # Check if the selected item is a real host item, not a placeholder
        if is_host_selected and selected_items[0].data(Qt.UserRole) is None: # Placeholder like "No hosts..."
            is_host_selected = False

        self.edit_host_button.setEnabled(is_host_selected)
        self.delete_host_button.setEnabled(is_host_selected)

    def load_host_list(self):
        current_selection_id = None
        if self.host_list_widget.currentItem() and self.host_list_widget.currentItem().data(Qt.UserRole) is not None:
            current_selection_id = self.host_list_widget.currentItem().data(Qt.UserRole)

        self.host_list_widget.clear()
        try:
            hosts = database.get_all_ssh_hosts()
            if not hosts:
                no_hosts_item = QListWidgetItem("No hosts configured yet. Click 'Add New Host'.")
                no_hosts_item.setTextAlignment(Qt.AlignCenter)
                no_hosts_item.setFlags(no_hosts_item.flags() & ~Qt.ItemIsSelectable) # Make it unselectable
                self.host_list_widget.addItem(no_hosts_item)
            else:
                for host in hosts:
                    # Customize item display later to include more info and status indicator
                    item_text = f"{host['name']} ({host['username']}@{host['hostname']}:{host['port']})"
                    list_item = QListWidgetItem(item_text)
                    list_item.setData(Qt.UserRole, host['id']) # Store host ID in the item
                    self.host_list_widget.addItem(list_item)
        except Exception as e:
            print(f"Error loading hosts: {e}")
            # Potentially show an error message in the UI
            error_item = QListWidgetItem(f"Error loading hosts: {e}")
            error_item.setForeground(Qt.red) # Make error messages red
            error_item.setFlags(error_item.flags() & ~Qt.ItemIsSelectable)
            self.host_list_widget.addItem(error_item)

        if current_selection_id is not None:
            for i in range(self.host_list_widget.count()):
                item = self.host_list_widget.item(i)
                if item.data(Qt.UserRole) == current_selection_id:
                    item.setSelected(True)
                    self.host_list_widget.setCurrentItem(item)
                    break
        self.update_host_action_buttons_state()

    def open_add_host_dialog(self):
        dialog = SshHostDialog(parent=self)
        if dialog.exec(): # QDialog.exec() returns true if accepted
            data = dialog.get_data()
            try:
                host_id = database.add_ssh_host(
                    name=data["name"],
                    hostname=data["hostname"],
                    port=data["port"],
                    username=data["username"],
                    auth_method=data["auth_method"],
                    password=data["password"], # Will be None if auth_method is 'key'
                    key_path=data["key_path"]  # Will be None if auth_method is 'password'
                )
                if host_id:
                    self.load_host_list()
                    QMessageBox.information(self, "Success", f"Host '{data['name']}' added successfully.")
                    # Try to select the newly added host
                    for i in range(self.host_list_widget.count()):
                        item = self.host_list_widget.item(i)
                        if item.data(Qt.UserRole) == host_id:
                            self.host_list_widget.setCurrentItem(item)
                            break
                else:
                    QMessageBox.warning(self, "Database Error", f"Failed to add host '{data['name']}'. The name might already exist or there was a database issue.")
            except ValueError as ve: # Catch specific validation errors from database module
                 QMessageBox.critical(self, "Input Error", str(ve))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")

    def open_edit_host_dialog(self):
        selected_items = self.host_list_widget.selectedItems()
        if not selected_items:
            # This should ideally not be reached if button state is managed well
            QMessageBox.warning(self, "Selection Error", "Please select a host to edit.")
            return

        current_item = selected_items[0]
        host_id = current_item.data(Qt.UserRole)

        if host_id is None: # Should not happen if buttons are correctly enabled/disabled
            QMessageBox.warning(self, "Error", "Cannot edit this item. It might be a placeholder.")
            return

        host_details_row = database.get_ssh_host_by_id(host_id) # Returns a sqlite3.Row
        if not host_details_row:
            QMessageBox.critical(self, "Error", f"Could not retrieve details for host ID {host_id}. It might have been deleted elsewhere.")
            self.load_host_list() # Refresh list in case it's out of sync
            return

        # Convert sqlite3.Row to a dictionary for the dialog
        # Important: also fetch password for editing if auth_method is password
        host_data_dict = dict(host_details_row)
        # Password is not fetched by get_all_ssh_hosts for security/brevity in list.
        # It's also not in get_ssh_host_by_id by default in the current database.py
        # We need to ensure get_ssh_host_by_id *can* fetch password.
        # Let's assume get_ssh_host_by_id in database.py returns all fields including password.
        # If not, database.py needs an update or a specific function.
        # Current database.get_ssh_host_by_id fetches '*' so it includes password.

        dialog = SshHostDialog(host_data=host_data_dict, parent=self)
        if dialog.exec():
            data = dialog.get_data()
            try:
                success = database.update_ssh_host(
                    host_id=host_id,
                    name=data["name"],
                    hostname=data["hostname"],
                    port=data["port"],
                    username=data["username"],
                    auth_method=data["auth_method"],
                    password=data["password"], # Will be None if auth_method is 'key'
                    key_path=data["key_path"]  # Will be None if auth_method is 'password'
                )
                if success:
                    self.load_host_list() # Reload to reflect changes
                    QMessageBox.information(self, "Success", f"Host '{data['name']}' updated successfully.")
                else:
                    QMessageBox.warning(self, "Database Error", f"Failed to update host '{data['name']}'. The name might already conflict or there was a database issue.")
            except ValueError as ve: # Catch specific validation errors from database module
                 QMessageBox.critical(self, "Input Error", str(ve))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"An unexpected error occurred while updating: {e}")

    def delete_selected_host(self):
        selected_items = self.host_list_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Selection Error", "Please select a host to delete.")
            return

        current_item = selected_items[0]
        host_id = current_item.data(Qt.UserRole)

        # Attempt to get a more user-friendly name for the confirmation dialog
        host_name_for_dialog = "the selected host"
        try:
            host_name_for_dialog = current_item.text().split(' (')[0]
        except:
            pass # Keep default if parsing fails

        if host_id is None: # Should not happen
            QMessageBox.warning(self, "Error", "Cannot delete this item. It might be a placeholder.")
            return

        reply = QMessageBox.question(self, "Confirm Deletion",
                                     f"Are you sure you want to delete '{host_name_for_dialog}'?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            try:
                if database.delete_ssh_host(host_id):
                    self.load_host_list()
                    QMessageBox.information(self, "Success", f"Host '{host_name_for_dialog}' deleted successfully.")
                else:
                    # This case might occur if the host was already deleted by another process
                    QMessageBox.warning(self, "Database Error", f"Failed to delete host '{host_name_for_dialog}'. It might have already been deleted.")
            except Exception as e:
                 QMessageBox.critical(self, "Error", f"An unexpected error occurred while deleting: {e}")

    def create_project_config_page(self):
        page_widget = QWidget()
        layout = QVBoxLayout(page_widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        title_label = QLabel("Project Configuration")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(title_label)

        self.project_list_widget = QListWidget()
        self.project_list_widget.setStyleSheet("""
            QListWidget {
                border: 1px solid #DCDCDC;
                border-radius: 6px;
                outline: 0;
            }
            QListWidget::item {
                padding: 12px 15px;
                border-bottom: 1px solid #EAEAEA;
                background-color: white;
            }
            QListWidget::item:last-child {
                border-bottom: none;
            }
            QListWidget::item:selected {
                background-color: #007AFF;
                color: white;
                border-bottom: 1px solid #007AFF;
            }
            QListWidget::item:hover:!selected {
                background-color: #f7f7f7;
            }
        """)
        layout.addWidget(self.project_list_widget)

        action_buttons_layout = QHBoxLayout()
        self.add_project_button = QPushButton("Add New Project")
        # self.add_project_button.clicked.connect(self.open_add_project_dialog) # Connect later
        action_buttons_layout.addWidget(self.add_project_button)

        self.edit_project_button = QPushButton("Edit Selected Project")
        self.edit_project_button.setEnabled(False)
        # self.edit_project_button.clicked.connect(self.open_edit_project_dialog) # Connect later
        action_buttons_layout.addWidget(self.edit_project_button)

        self.delete_project_button = QPushButton("Delete Selected Project")
        self.delete_project_button.setStyleSheet("background-color: #ffdddd; color: #D8000C;")
        self.delete_project_button.setEnabled(False)
        # self.delete_project_button.clicked.connect(self.delete_selected_project) # Connect later
        action_buttons_layout.addWidget(self.delete_project_button)

        action_buttons_layout.addStretch()
        layout.addLayout(action_buttons_layout)

        self.add_project_button.clicked.connect(self.open_add_project_dialog)
        action_buttons_layout.addWidget(self.add_project_button)

        self.edit_project_button = QPushButton("Edit Selected Project")
        self.edit_project_button.setEnabled(False)
        self.edit_project_button.clicked.connect(self.open_edit_project_dialog)
        action_buttons_layout.addWidget(self.edit_project_button)

        self.delete_project_button = QPushButton("Delete Selected Project")
        self.delete_project_button.setStyleSheet("background-color: #ffdddd; color: #D8000C;")
        self.delete_project_button.setEnabled(False)
        self.delete_project_button.clicked.connect(self.delete_selected_project)
        action_buttons_layout.addWidget(self.delete_project_button)

        action_buttons_layout.addStretch()
        layout.addLayout(action_buttons_layout)

        self.project_list_widget.itemSelectionChanged.connect(self.update_project_action_buttons_state)
        self.load_project_list() # Initial load
        return page_widget

    def update_project_action_buttons_state(self):
        selected_items = self.project_list_widget.selectedItems()
        is_project_selected = len(selected_items) > 0
        if is_project_selected and selected_items[0].data(Qt.UserRole) is None: # Placeholder
            is_project_selected = False

        self.edit_project_button.setEnabled(is_project_selected)
        self.delete_project_button.setEnabled(is_project_selected)


    def load_project_list(self):
        current_selection_id = None
        if hasattr(self, 'project_list_widget') and self.project_list_widget.currentItem() and \
           self.project_list_widget.currentItem().data(Qt.UserRole) is not None:
            current_selection_id = self.project_list_widget.currentItem().data(Qt.UserRole)

        if not hasattr(self, 'project_list_widget'): # If called before UI fully initialized
            return

        self.project_list_widget.clear()
        try:
            projects = database.get_all_compile_projects()
            if not projects:
                no_projects_item = QListWidgetItem("No projects configured. Click 'Add New Project'.")
                no_projects_item.setTextAlignment(Qt.AlignCenter)
                no_projects_item.setFlags(no_projects_item.flags() & ~Qt.ItemIsSelectable)
                self.project_list_widget.addItem(no_projects_item)
            else:
                for project in projects:
                    item_text = f"{project['name']} (Remote Path: {project['remote_base_path']})"
                    list_item = QListWidgetItem(item_text)
                    list_item.setData(Qt.UserRole, project['id'])
                    self.project_list_widget.addItem(list_item)

            if current_selection_id is not None:
                for i in range(self.project_list_widget.count()):
                    item = self.project_list_widget.item(i)
                    if item.data(Qt.UserRole) == current_selection_id:
                        item.setSelected(True)
                        self.project_list_widget.setCurrentItem(item)
                        break
            # self.update_project_action_buttons_state() # Connect later
        except Exception as e:
            print(f"Error loading projects: {e}")
            error_item = QListWidgetItem(f"Error loading projects: {e}")
            error_item.setForeground(Qt.red)
            error_item.setFlags(error_item.flags() & ~Qt.ItemIsSelectable)
            self.project_list_widget.addItem(error_item)
        self.update_project_action_buttons_state() # Ensure button state is correct after loading

    def open_add_project_dialog(self):
        dialog = CompileProjectDialog(parent=self)
        if dialog.exec():
            data = dialog.get_data()
            try:
                project_id = database.add_compile_project(
                    name=data["name"],
                    remote_base_path=data["remote_base_path"],
                    compile_commands=data["compile_commands"],
                    artifact_path=data["artifact_path"]
                )
                if project_id:
                    self.load_project_list()
                    QMessageBox.information(self, "Success", f"Project '{data['name']}' added successfully.")
                    for i in range(self.project_list_widget.count()): # Try to select new item
                        item = self.project_list_widget.item(i)
                        if item.data(Qt.UserRole) == project_id:
                            self.project_list_widget.setCurrentItem(item)
                            break
                else:
                    QMessageBox.warning(self, "Database Error", f"Failed to add project '{data['name']}'. Name might already exist.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")

    def open_edit_project_dialog(self):
        selected_items = self.project_list_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Selection Error", "Please select a project to edit.")
            return

        current_item = selected_items[0]
        project_id = current_item.data(Qt.UserRole)
        if project_id is None:
             QMessageBox.warning(self, "Error", "Cannot edit this item.")
             return

        project_details_row = database.get_compile_project_by_id(project_id)
        if not project_details_row:
            QMessageBox.critical(self, "Error", f"Could not retrieve details for project ID {project_id}.")
            self.load_project_list()
            return

        dialog = CompileProjectDialog(project_data=dict(project_details_row), parent=self)
        if dialog.exec():
            data = dialog.get_data()
            try:
                success = database.update_compile_project(
                    project_id=project_id,
                    name=data["name"],
                    remote_base_path=data["remote_base_path"],
                    compile_commands=data["compile_commands"],
                    artifact_path=data["artifact_path"]
                )
                if success:
                    self.load_project_list()
                    QMessageBox.information(self, "Success", f"Project '{data['name']}' updated successfully.")
                else:
                    QMessageBox.warning(self, "Database Error", f"Failed to update project '{data['name']}'. Name might conflict.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"An unexpected error occurred while updating: {e}")

    def delete_selected_project(self):
        selected_items = self.project_list_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Selection Error", "Please select a project to delete.")
            return

        current_item = selected_items[0]
        project_id = current_item.data(Qt.UserRole)
        project_name = current_item.text().split(' (')[0]
        if project_id is None:
            QMessageBox.warning(self, "Error", "Cannot delete this item.")
            return

        reply = QMessageBox.question(self, "Confirm Deletion",
                                     f"Are you sure you want to delete project '{project_name}'?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            try:
                if database.delete_compile_project(project_id):
                    self.load_project_list()
                    QMessageBox.information(self, "Success", f"Project '{project_name}' deleted successfully.")
                else:
                    QMessageBox.warning(self, "Database Error", f"Failed to delete project '{project_name}'.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"An unexpected error occurred while deleting: {e}")

    def create_compile_execution_page(self):
        page_widget = QWidget()
        main_layout = QVBoxLayout(page_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Title
        title_label = QLabel("Compile & Run Project")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        main_layout.addWidget(title_label)

        # --- Top Selection Area ---
        selection_layout = QGridLayout() # Use QGridLayout for better alignment
        selection_layout.setSpacing(10)

        selection_layout.addWidget(QLabel("Select Project:"), 0, 0)
        self.compile_project_combo = QComboBox()
        self.compile_project_combo.setPlaceholderText("Choose a project...")
        # self.compile_project_combo.currentIndexChanged.connect(self.update_selected_project_info)
        selection_layout.addWidget(self.compile_project_combo, 0, 1)

        selection_layout.addWidget(QLabel("Select Host:"), 1, 0)
        self.compile_host_combo = QComboBox()
        self.compile_host_combo.setPlaceholderText("Choose a host...")
        # self.compile_host_combo.currentIndexChanged.connect(self.update_selected_host_info)
        selection_layout.addWidget(self.compile_host_combo, 1, 1)

        # Stretch the combo boxes to take available space
        selection_layout.setColumnStretch(1, 1)

        main_layout.addLayout(selection_layout)

        # --- Selected Info Area ---
        self.selected_info_label = QLabel("Project: [None] | Host: [None]")
        self.selected_info_label.setStyleSheet("font-style: italic; color: #555; margin-bottom: 10px;")
        main_layout.addWidget(self.selected_info_label)

        # --- Compile Log Area ---
        log_label = QLabel("Compilation Log:")
        main_layout.addWidget(log_label)
        self.compile_log_display = QTextEdit()
        self.compile_log_display.setReadOnly(True)
        self.compile_log_display.setFontFamily("monospace")
        self.compile_log_display.setStyleSheet("""
            QTextEdit {
                background-color: #F7F7F7; /* Slightly off-white for log */
                border: 1px solid #DCDCDC;
                border-radius: 6px;
                color: #333333; /* Dark gray text */
                font-size: 13px; /* Monospace font can be smaller */
                padding: 8px;
            }
        """)
        main_layout.addWidget(self.compile_log_display, 1) # Log display takes stretch factor

        # --- Compile Control Area ---
        control_layout = QHBoxLayout()
        self.compile_status_label = QLabel("Status: Idle")
        control_layout.addWidget(self.compile_status_label)
        control_layout.addStretch()

        self.start_compile_button = QPushButton("Start Compilation")
        self.start_compile_button.clicked.connect(self.start_compilation_process)
        self.start_compile_button.setIcon(self.style().standardIcon(getattr(QStyle, "SP_MediaPlay", QStyle.StandardPixmap.SP_MediaPlay))) # Example Icon
        control_layout.addWidget(self.start_compile_button)

        self.interrupt_compile_button = QPushButton("Interrupt")
        self.interrupt_compile_button.clicked.connect(self.interrupt_compilation_process)
        self.interrupt_compile_button.setEnabled(False) # Enabled only during compilation
        self.interrupt_compile_button.setIcon(self.style().standardIcon(getattr(QStyle, "SP_MediaStop", QStyle.StandardPixmap.SP_MediaStop))) # Example Icon
        self.interrupt_compile_button.setStyleSheet("background-color: #e74c3c;") # Reddish color
        control_layout.addWidget(self.interrupt_compile_button)

        self.clear_log_button = QPushButton("Clear Log")
        self.clear_log_button.clicked.connect(self.compile_log_display.clear)
        control_layout.addWidget(self.clear_log_button)


        main_layout.addLayout(control_layout)

        self.load_projects_into_combobox()
        self.load_hosts_into_combobox()

        # Connect signals for updating selected info label
        self.compile_project_combo.currentIndexChanged.connect(self._update_selected_info_text)
        self.compile_host_combo.currentIndexChanged.connect(self._update_selected_info_text)
        self._update_selected_info_text() # Initial call

        # --- Artifacts Area ---
        artifacts_groupbox = QGroupBox("Compiled Artifacts")
        artifacts_groupbox.setStyleSheet("font-size: 16px; font-weight: bold; margin-top: 5px;") # Style groupbox title
        artifacts_layout = QVBoxLayout(artifacts_groupbox)

        self.artifacts_list_widget = QListWidget()
        self.artifacts_list_widget.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.artifacts_list_widget.setStyleSheet("""
            QListWidget {
                border: 1px solid #DCDCDC;
                border-radius: 6px;
                outline: 0;
            }
            QListWidget::item {
                padding: 10px 12px; /* Slightly less padding than main lists */
                border-bottom: 1px solid #EAEAEA;
                background-color: white;
            }
            QListWidget::item:last-child {
                border-bottom: none;
            }
            QListWidget::item:selected {
                background-color: #007AFF;
                color: white;
                border-bottom: 1px solid #007AFF;
            }
            QListWidget::item:hover:!selected {
                background-color: #f7f7f7;
            }
        """)
        artifacts_layout.addWidget(self.artifacts_list_widget)

        artifact_actions_layout = QHBoxLayout()
        self.refresh_artifacts_button = QPushButton("Refresh Artifacts")
        self.refresh_artifacts_button.clicked.connect(self.refresh_remote_artifacts)
        artifact_actions_layout.addWidget(self.refresh_artifacts_button)

        self.download_artifacts_button = QPushButton("Download Selected")
        self.download_artifacts_button.clicked.connect(self.download_selected_artifacts)
        artifact_actions_layout.addWidget(self.download_artifacts_button)
        artifact_actions_layout.addStretch()

        artifacts_layout.addLayout(artifact_actions_layout)
        main_layout.addWidget(artifacts_groupbox)

        # Disable artifact controls initially, enable after successful compilation or manual refresh
        self.refresh_artifacts_button.setEnabled(False)
        self.download_artifacts_button.setEnabled(False)


        return page_widget

    def _update_selected_info_text(self):
        project_name = self.compile_project_combo.currentText()
        if self.compile_project_combo.currentIndex() == -1 or not self.compile_project_combo.itemData(self.compile_project_combo.currentIndex()):
            project_name = "[None]"

        host_name = self.compile_host_combo.currentText()
        if self.compile_host_combo.currentIndex() == -1 or not self.compile_host_combo.itemData(self.compile_host_combo.currentIndex()):
            host_name = "[None]"

        self.selected_info_label.setText(f"Project: {project_name} | Host: {host_name}")


    def load_projects_into_combobox(self):
        self.compile_project_combo.clear()
        self.compile_project_combo.addItem("Choose a project...", None) # Placeholder
        try:
            projects = database.get_all_compile_projects()
            for project in projects:
                self.compile_project_combo.addItem(f"{project['name']}", project['id'])
        except Exception as e:
            print(f"Error loading projects into combobox: {e}")
            self.compile_project_combo.addItem(f"Error: {e}", None)

    def load_hosts_into_combobox(self):
        self.compile_host_combo.clear()
        self.compile_host_combo.addItem("Choose a host...", None) # Placeholder
        try:
            hosts = database.get_all_ssh_hosts() # Assuming this gets minimal info needed
            for host in hosts:
                # We might want to store more than just ID, e.g., hostname for direct use
                self.compile_host_combo.addItem(f"{host['name']} ({host['username']}@{host['hostname']})", host['id'])
        except Exception as e:
            print(f"Error loading hosts into combobox: {e}")
            self.compile_host_combo.addItem(f"Error: {e}", None)

    # Placeholder for actual SSH connection management
    # This will be expanded significantly
    _ssh_clients = {} # host_id: paramiko.SSHClient()

    def get_ssh_client(self, host_id: int) -> Optional[paramiko.SSHClient]:
        """
        Retrieves or establishes an SSH client for the given host_id.
        This is a simplified placeholder. Real implementation needs connection status,
        re-authentication, error handling, etc.
        """
        if host_id in self._ssh_clients and self._ssh_clients[host_id].get_transport() and self._ssh_clients[host_id].get_transport().is_active():
            return self._ssh_clients[host_id]

        host_config = database.get_ssh_host_by_id(host_id)
        if not host_config:
            QMessageBox.critical(self, "SSH Error", f"Host configuration for ID {host_id} not found.")
            return None

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.compile_status_label.setText(f"Status: Connecting to {host_config['name']}...")
            QApplication.processEvents()
            if host_config["auth_method"] == "password":
                client.connect(host_config["hostname"], port=host_config["port"], username=host_config["username"],
                               password=host_config["password"], timeout=10, allow_agent=False, look_for_keys=False)
            elif host_config["auth_method"] == "key":
                client.connect(host_config["hostname"], port=host_config["port"], username=host_config["username"],
                               key_filename=host_config["key_path"], timeout=10)
            else:
                QMessageBox.critical(self, "SSH Error", f"Unsupported auth method for host {host_config['name']}.")
                self.compile_status_label.setText(f"Status: Connection failed to {host_config['name']}")
                return None

            self._ssh_clients[host_id] = client
            self.compile_status_label.setText(f"Status: Connected to {host_config['name']}")
            return client
        except Exception as e:
            self._ssh_clients.pop(host_id, None) # Remove if connection failed
            QMessageBox.critical(self, "SSH Connection Error", f"Failed to connect to {host_config['name']}: {e}")
            self.compile_status_label.setText(f"Status: Connection failed to {host_config['name']}")
            return None

    def close_ssh_client(self, host_id: int):
        if host_id in self._ssh_clients:
            try:
                self._ssh_clients[host_id].close()
            except Exception as e:
                print(f"Error closing SSH client for host {host_id}: {e}")
            del self._ssh_clients[host_id]
            print(f"SSH client for host {host_id} closed.")

    # When the main window closes, close all active SSH connections
    def closeEvent(self, event):
        if hasattr(self, 'compilation_thread') and self.compilation_thread and self.compilation_thread.isRunning():
            self.compilation_thread.stop()
            self.compilation_thread.wait() # Wait for thread to finish

        host_ids = list(self._ssh_clients.keys()) # Iterate over a copy of keys
        for host_id in host_ids:
            self.close_ssh_client(host_id)
        super().closeEvent(event)

    def start_compilation_process(self):
        project_id = self.compile_project_combo.currentData()
        host_id = self.compile_host_combo.currentData()

        if not project_id:
            QMessageBox.warning(self, "Selection Error", "Please select a compile project.")
            return
        if not host_id:
            QMessageBox.warning(self, "Selection Error", "Please select a host.")
            return

        project_details = database.get_compile_project_by_id(project_id)
        if not project_details:
            QMessageBox.critical(self, "Error", f"Failed to retrieve details for project ID {project_id}.")
            return

        # Get or establish SSH connection
        ssh_client = self.get_ssh_client(host_id) # This might show its own error dialogs
        if not ssh_client:
            # get_ssh_client already shows a message if it fails
            self.compile_status_label.setText("Status: SSH Connection Failed")
            return

        self.compile_log_display.clear()
        self.append_log_message(f"Starting compilation for project: {project_details['name']} on host...\n")

        self.compilation_thread = CompilationThread(
            ssh_client=ssh_client,
            commands=project_details['compile_commands'],
            remote_base_path=project_details['remote_base_path']
        )
        self.compilation_thread.log_received.connect(self.append_log_message)
        self.compilation_thread.status_changed.connect(self.update_compile_status)
        self.compilation_thread.compilation_finished.connect(self.on_compilation_finished)

        self.compilation_thread.start()
        self.start_compile_button.setEnabled(False)
        self.interrupt_compile_button.setEnabled(True)
        self.compile_project_combo.setEnabled(False) # Prevent changes during compilation
        self.compile_host_combo.setEnabled(False)

    def interrupt_compilation_process(self):
        if hasattr(self, 'compilation_thread') and self.compilation_thread and self.compilation_thread.isRunning():
            self.compile_status_label.setText("Status: Interrupting...")
            self.compilation_thread.stop()
            # Button states will be managed by on_compilation_finished
        else:
            self.append_log_message("No active compilation process to interrupt.\n")
            self.interrupt_compile_button.setEnabled(False) # Should not happen if logic is correct

    def append_log_message(self, message: str):
        self.compile_log_display.moveCursor(QTextCursor.End)
        self.compile_log_display.insertPlainText(message)
        self.compile_log_display.moveCursor(QTextCursor.End) # Ensure auto-scroll

    def update_compile_status(self, status_message: str):
        self.compile_status_label.setText(f"Status: {status_message}")

    def on_compilation_finished(self, success: bool):
        self.start_compile_button.setEnabled(True)
        self.interrupt_compile_button.setEnabled(False)
        self.compile_project_combo.setEnabled(True)
        self.compile_host_combo.setEnabled(True)

        if success:
            self.compile_status_label.setText("Status: Compilation Successful")
            # Optionally, trigger artifact loading here if part of this stage's scope
            QMessageBox.information(self, "Compilation Finished", "The compilation process completed successfully.")
        else:
            # Status label should already be set by CompilationThread (e.g. "Failed", "Interrupted", "Error")
            # So, just ensure it's not "Compiling..."
            if "Compiling" in self.compile_status_label.text() or "Preparing" in self.compile_status_label.text():
                 self.compile_status_label.setText("Status: Compilation Ended (with issues or interrupted)")
            QMessageBox.warning(self, "Compilation Finished", "The compilation process finished with errors or was interrupted.")

        # It's important NOT to close the SSH client here automatically,
        # as the user might want to download artifacts or run another compilation.
        # SSH clients are managed via _ssh_clients and closed on window exit or explicitly.

        # Clean up the thread object
        if hasattr(self, 'compilation_thread'):
            self.compilation_thread.quit() # Ask thread's event loop to exit (if it had one)
            self.compilation_thread.wait(2000) # Wait up to 2s for thread to terminate
            if self.compilation_thread.isRunning():
                print("Warning: Compilation thread did not terminate gracefully.")
                # self.compilation_thread.terminate() # Force terminate if still running (use with caution)
            del self.compilation_thread

        if success: # If compilation was successful, try to refresh artifacts
            self.refresh_remote_artifacts()


    def refresh_remote_artifacts(self):
        project_id = self.compile_project_combo.currentData()
        host_id = self.compile_host_combo.currentData()

        if not project_id:
            QMessageBox.warning(self, "Info", "Please select a project first.")
            return
        if not host_id:
            QMessageBox.warning(self, "Info", "Please select a host first.")
            return

        project_details = database.get_compile_project_by_id(project_id)
        if not project_details:
            QMessageBox.critical(self, "Error", f"Failed to retrieve project details for ID {project_id}.")
            return

        remote_artifact_path = project_details['artifact_path']
        if not remote_artifact_path:
            QMessageBox.warning(self, "Project Config Error", "Selected project does not have an artifact path configured.")
            return

        ssh_client = self.get_ssh_client(host_id)
        if not ssh_client:
            QMessageBox.critical(self, "SSH Error", "SSH connection is not available.")
            return

        self.artifacts_list_widget.clear()
        self.artifacts_list_widget.addItem("Loading artifacts...")
        QApplication.processEvents()

        try:
            sftp = ssh_client.open_sftp()
            try:
                # Check if path exists and is a directory
                stat_info = sftp.stat(remote_artifact_path)
                if not stat.S_ISDIR(stat_info.st_mode):
                    self.artifacts_list_widget.clear()
                    self.artifacts_list_widget.addItem(f"Error: Path is not a directory: {remote_artifact_path}")
                    self.refresh_artifacts_button.setEnabled(True) # Allow retry
                    self.download_artifacts_button.setEnabled(False)
                    sftp.close()
                    return

                file_list = sftp.listdir_attr(remote_artifact_path)
                self.artifacts_list_widget.clear()
                if not file_list:
                    self.artifacts_list_widget.addItem("No artifacts found in the directory.")
                else:
                    for attr in file_list:
                        # We're primarily interested in files, could filter out directories if needed
                        # For now, list everything and show size for files.
                        file_type = "DIR" if stat.S_ISDIR(attr.st_mode) else "FILE"
                        item_text = f"{attr.filename} ({file_type}, Size: {attr.st_size if file_type == 'FILE' else 'N/A'})"
                        item = QListWidgetItem(item_text)
                        item.setData(Qt.UserRole, attr.filename) # Store filename for download
                        item.setData(Qt.UserRole + 1, file_type) # Store type
                        self.artifacts_list_widget.addItem(item)

                self.download_artifacts_button.setEnabled(len(file_list) > 0)

            except FileNotFoundError:
                self.artifacts_list_widget.clear()
                self.artifacts_list_widget.addItem(f"Artifact directory not found: {remote_artifact_path}")
                self.download_artifacts_button.setEnabled(False)
            except Exception as e:
                self.artifacts_list_widget.clear()
                self.artifacts_list_widget.addItem(f"Error listing artifacts: {str(e)}")
                self.download_artifacts_button.setEnabled(False)
            finally:
                if sftp:
                    sftp.close()
        except Exception as e: # For sftp client opening error
            self.artifacts_list_widget.clear()
            self.artifacts_list_widget.addItem(f"SFTP Error: {str(e)}")
            self.download_artifacts_button.setEnabled(False)

        self.refresh_artifacts_button.setEnabled(True) # Always re-enable refresh button

    def download_selected_artifacts(self):
        selected_items = self.artifacts_list_widget.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select one or more artifacts to download.")
            return

        project_id = self.compile_project_combo.currentData()
        host_id = self.compile_host_combo.currentData()
        if not project_id or not host_id: # Should not happen if buttons are enabled correctly
            QMessageBox.warning(self, "Error", "Project or Host not selected.")
            return

        project_details = database.get_compile_project_by_id(project_id)
        if not project_details: return # Should be caught earlier

        remote_artifact_base_path = project_details['artifact_path']

        local_save_dir = QFileDialog.getExistingDirectory(self, "Select Directory to Save Artifacts")
        if not local_save_dir:
            return # User cancelled

        ssh_client = self.get_ssh_client(host_id)
        if not ssh_client:
            QMessageBox.critical(self, "SSH Error", "SSH connection is not available for download.")
            return

        sftp = None
        try:
            sftp = ssh_client.open_sftp()
            # Basic progress tracking
            # TODO: Implement QProgressDialog for better UX
            total_files = len(selected_items)
            downloaded_count = 0

            self.compile_status_label.setText(f"Status: Downloading 0/{total_files} artifacts...")
            QApplication.processEvents()


            for item in selected_items:
                filename = item.data(Qt.UserRole)
                file_type = item.data(Qt.UserRole + 1)

                if file_type == "DIR":
                    self.append_log_message(f"Skipping directory download: {filename} (not yet implemented).\n")
                    total_files -=1 # Adjust total for skipped dirs
                    if total_files == 0 and downloaded_count == 0 : # if only dirs were selected
                         self.compile_status_label.setText("Status: No files selected for download.")
                    elif downloaded_count == total_files: # if all actual files are downloaded
                         self.compile_status_label.setText(f"Status: Download complete ({downloaded_count}/{total_files}).")
                    else: # update progress
                        self.compile_status_label.setText(f"Status: Downloading {downloaded_count}/{total_files} artifacts...")
                    QApplication.processEvents()
                    continue

                remote_full_path = f"{remote_artifact_base_path.rstrip('/')}/{filename}"
                local_full_path = os.path.join(local_save_dir, filename)

                try:
                    self.append_log_message(f"Downloading {filename} to {local_full_path}...\n")
                    QApplication.processEvents()

                    # Simple SFTP get with callback for progress (very basic)
                    # For a real progress bar, a separate thread for download and more complex callback is needed.
                    # This is a blocking download per file.
                    sftp.get(remote_full_path, local_full_path)
                    self.append_log_message(f"Successfully downloaded {filename}.\n")
                    downloaded_count += 1
                    self.compile_status_label.setText(f"Status: Downloading {downloaded_count}/{total_files} artifacts...")
                    QApplication.processEvents()

                except Exception as e:
                    self.append_log_message(f"Failed to download {filename}: {e}\n")
                    QMessageBox.warning(self, "Download Error", f"Failed to download {filename}: {e}")

            if downloaded_count > 0:
                QMessageBox.information(self, "Download Complete",
                                        f"{downloaded_count} artifact(s) downloaded to {local_save_dir}.")
            elif total_files == 0 : # Only directories were selected initially
                 QMessageBox.information(self, "Download Info", "No files were selected for download (directories are skipped).")
            else: # No files downloaded, but some were attempted
                 QMessageBox.warning(self, "Download Failed", "No artifacts were successfully downloaded.")

            self.compile_status_label.setText(f"Status: Download finished ({downloaded_count}/{total_files}).")

        except Exception as e:
            QMessageBox.critical(self, "SFTP Error", f"An error occurred during SFTP operation: {e}")
            self.compile_status_label.setText("Status: SFTP Error.")
        finally:
            if sftp:
                sftp.close()


    def load_styles(self):
        # More global styles can be applied here if needed
        self.setStyleSheet("""
            QMainWindow {
                background-color: #ffffff; /* White background for the window */
            }
            QLabel {
                font-size: 14px; /* Base font size */
            }
            QPushButton {
                background-color: #007AFF;
                color: white;
                border: none;
                padding: 10px 15px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #005ecb;
            }
            QPushButton:pressed {
                background-color: #004a9e;
            }
            QPushButton:disabled {
                background-color: #d3d3d3;
                color: #a0a0a0;
            }
        """)

if __name__ == "__main__":
    # Ensure database is initialized before starting the app
    import database # Import here to use its functions
    database.create_tables() # Create tables if they don't exist

    app = QApplication(sys.argv)
    window = MainWindow()
    window.load_styles() # Apply global styles
    window.show()
    sys.exit(app.exec())
