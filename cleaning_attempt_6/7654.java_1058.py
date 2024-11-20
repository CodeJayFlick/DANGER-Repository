import subprocess
import time
from datetime import timedelta
import logging

class ExternalProgramLoginModule:
    def __init__(self):
        self.subject = None
        self.callback_handler = None
        self.options = {}
        self.user = None
        self.username = None
        self.password = None
        self.cmd_array = []
        self.ext_program_name = ''
        self.success = False
        self.committed = False

    def initialize(self, subject, callback_handler, shared_state, options):
        self.subject = subject
        self.callback_handler = callback_handler
        self.options = options

    def login(self) -> bool:
        self.read_options()
        self.get_name_and_password()
        self.call_external_program()
        self.success = True
        self.user = UserPrincipal(self.username)
        return True

    def commit(self):
        if not self.success:
            return False
        if not self.subject.is_readonly():
            if not self.user.implies(self.subject):
                self.subject.get_principals().add(self.user)
        self.committed = True
        return True

    def abort(self) -> bool:
        if not self.success:
            return False
        if not self.committed:
            self.success = False
            self.cleanup()
        else:
            self.logout()
        return True

    def logout(self):
        if self.subject.is_readonly():
            self.cleanup()
            raise LoginException("Subject is read-only")
        self.subject.get_principals().remove(self.user)
        self.cleanup()
        self.success = False
        self.committed = False

    def cleanup(self):
        self.user = None
        self.username = None
        if self.password:
            for char in self.password:
                char = '\0'
            self.password = None

    def read_options(self) -> None:
        timeout_str = self.options.get('TIMEOUT')
        if timeout_str is not None:
            try:
                self.timeout_ms = int(timeout_str)
            except ValueError:
                pass
        self.read_ext_prog_options()

    def call_external_program(self):
        process = subprocess.Popen(self.cmd_array, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

        try:
            output, error = process.communicate(input=f"{self.username}\n{password}\n".encode())
            if process.returncode != 0:
                raise FailedLoginException(f"Login failed: external command exited with error {process.returncode}")
        except subprocess.CalledProcessError as e:
            logging.error("Exception when executing %s:%s", self.ext_program_name, str(e))
            raise LoginException("Error executing external program")

    def read_ext_prog_options(self) -> None:
        ext_program = self.options.get('PROGRAM')
        if not ext_program or not isinstance(ext_program, str):
            raise LoginException(f"Missing {PROGRAM_OPTION_NAME}=path_to_external_program in options")
        file_path = Path(ext_program).absolute()
        if not file_path.exists():
            raise LoginException(f"Bad {PROGRAM_OPTION_NAME}=path_to_external_program in options")

    def get_name_and_password(self) -> None:
        user_prompt = self.options.get('USER_PROMPT', "User name").encode()
        pass_prompt = self.options.get('PASSWORD_ PROMPT', "Password").encode()

        if not (username and password):
            try:
                callback_handler.handle([NameCallback(user_prompt), PasswordCallback(pass_prompt, False)])
                username = ncb.name
                password = pcb.password
                pcb.clear_password()
            except (IOException, UnsupportedCallbackException) as e:
                raise LoginException(f"Error during callback: {str(e)}")

        if not (username and password):
            raise LoginException("Failed to get username or password")
