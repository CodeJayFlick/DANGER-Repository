import tkinter as tk
from tkinter import simpledialog
from tkinter.messagebox import showinfo, askyesno

class DefaultClientAuthenticator:
    def __init__(self):
        self.authenticator = Authenticator()

    class ServerPasswordPrompt(tk.Toplevel):
        def __init__(self, title, server_type, server_name, name_cb=None, pass_cb=None,
                     choice_cb=None, anonymous_cb=None, error_msg=None):
            super().__init__()
            self.title = title
            self.server_type = server_type
            self.server_name = server_name
            self.name_cb = name_cb
            self.pass_cb = pass_cb
            self.choice_cb = choice_cb
            self.anonymous_cb = anonymous_cb
            self.error_msg = error_msg

        def run(self):
            password_dialog = tk.Toplevel()
            if self.name_cb:
                username = simpledialog.askstring("Username", "Name:")
                Preferences.set_property("PasswordPrompt.Name", username)
            else:
                username = ClientUtil.get_username()

            if self.choice_cb:
                choice_prompt = self.choice_cb.prompt
                choices = self.choice_cb.choices
            else:
                choice_prompt = None
                choices = None

            password_dialog.title(self.title)
            password_dialog.label("Server Type:", self.server_type)
            password_dialog.label("Server Name:", self.server_name)

            if error_msg is not None:
                password_dialog.set_error_text(error_msg)

            root_frame = DockingWindowManager.get_active_instance().get_root_frame()
            docking_window_manager.show_dialog(root_frame, password_dialog)

        def ok_was_pressed(self):
            return True

    class Authenticator:
        def get_password_authentication(self):
            msg.debug("PasswordAuthentication requested for " + self.requesting_url)
            name_cb = None
            if not "NO_NAME".equals(self.requesting_scheme()):
                name_cb = NameCallback("Name:", ClientUtil.get_username())

            prompt = self.requesting_prompt()
            if prompt is None:
                prompt = "Password:"

            pass_cb = PasswordCallback(prompt, False)

            server_password_prompt = ServerPasswordPrompt(
                "Connection Authentication", "Server",
                self.requesting_host(), name_cb, pass_cb,
                choice_cb=None, anonymous_cb=None, error_msg=None
            )
            SystemUtilities.run_swing_now(server_password_prompt)
            if server_password_prompt.ok_was_pressed():
                return PasswordAuthentication(name_cb.name() if name_cb else None,
                                                 pass_cb.get_password())
            return None

    def get_authenticator(self):
        return self.authenticator

    def is_ssh_key_available(self):
        return False  # GUI does not currently support SSH authentication

    def process_ssh_signature_callbacks(self, server_name, name_cb, ssh_cb):
        return False

    def process_password_callbacks(self, title, server_type, server_name,
                                    name_cb, pass_cb, choice_cb=None, anonymous_cb=None,
                                    login_error=None):
        server_password_prompt = ServerPasswordPrompt(
            title, server_type, server_name, name_cb, pass_cb, choice_cb, anonymous_cb, login_error
        )
        SystemUtilities.run_swing_now(server_password_prompt)
        return server_password_prompt.ok_was_pressed()

    def prompt_for_reconnect(self, parent, message):
        return askyesno("Lost Connection to Server", message) == 1

    def get_new_password(self, parent, server_info, username):
        password_change_dialog = PasswordChangeDialog(
            "Change Password", "Repository Server", server_info, username
        )
        SystemUtilities.run_swing_now(password_change_dialog)
        return password_change_dialog.get_password()

class NameCallback:
    def __init__(self, prompt, default_value=None):
        self.prompt = prompt
        self.default_value = default_value

    def get_name(self):
        if self.default_value is not None:
            return self.default_value
        else:
            return simpledialog.askstring("Username", "Name:")

class PasswordCallback:
    def __init__(self, prompt, echo_char=None):
        self.prompt = prompt
        self.echo_char = echo_char

    def get_password(self):
        password = simpledialog.askpassword("Password:", "Enter your password:")
        return password.encode()

# Usage example:

default_client_authenticator = DefaultClientAuthenticator()
authenticator = default_client_authenticator.get_authenticator()
