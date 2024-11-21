Here is a translation of the Java code into equivalent Python:

```Python
import xml.etree.ElementTree as ET
from getpass import getuser
from urllib.parse import urlparse

class JAASAuthenticationModule:
    def __init__(self, login_context_name: str, allow_user_to_specify_name: bool, jaas_config_file_path: str):
        self.login_context_name = login_context_name
        self.allow_user_to_specify_name = allow_user_to_specify_name
        self.jaas_config_file_path = jaas_config_file_path

    def get_jaas_config(self) -> ET.Element:
        try:
            tree = ET.parse(self.jaas_config_file_path)
            root = tree.getroot()
            return root.find(f".//{self.login_context_name}")
        except Exception as e:
            raise ValueError("JAAS configuration error") from e

    def authenticate(self, user_mgr: object, subject: object, callbacks: list) -> str:
        principal = getuser()

        try:
            jaas_config = self.get_jaas_config()
            login_context = LoginContext(jaas_config)
            login_context.login(callbacks)

        except Exception as e:
            raise ValueError("JAAS configuration error") from e

        finally:
            if callbacks and isinstance(callbacks[0], PasswordCallback):
                callback = callbacks[0]
                callback.clear_password()

        return principal if not self.allow_user_to_specify_name else (callbacks[1].name if len(callbacks) > 1 else None)

    def get_authentication_callbacks(self, allow_user_to_specify_name: bool) -> list:
        # We don't know for sure what callbacks the JAAS LoginModule is going to throw at us
        # during the login() method. Therefore, to keep things simple, we are going to limit
        # the supported JAAS LoginModules to ones that only use Name and Password callbacks.
        return [NameCallback(), PasswordCallback()]

    def anonymous_callbacks_allowed(self) -> bool:
        return False

    def is_name_callback_allowed(self) -> bool:
        return self.allow_user_to_specify_name


class LoginContext:
    def __init__(self, jaas_config: ET.Element):
        self.jaas_config = jaas_config

    def login(self, callbacks: list):
        # this is where the callback is triggered
        pass  # implement me!

class NameCallback:
    def __init__(self):
        self.name = None

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value


class PasswordCallback:
    def __init__(self):
        self.password = None

    @property
    def password(self) -> str:
        return self._password

    @password.setter
    def password(self, value: str):
        self._password = value

    def clear_password(self):
        self.password = None


def copy_callback_values(src_instances: list, dest_instances: list, principal: str) -> str:
    src_pcb = next((callback for callback in src_instances if isinstance(callback, PasswordCallback)), None)
    src_ncb = next((callback for callback in src_instances if isinstance(callback, NameCallback)), None)

    user_name = None
    dest_ncb = next((callback for callback in dest_instances if isinstance(callback, NameCallback)), None)
    if dest_ncb:
        user_name = (src_ncb.name if self.allow_user_to_specify_name and src_ncb else principal)
        dest_ncb.name = user_name

    dest_pcb = next((callback for callback in dest_instances if isinstance(callback, PasswordCallback)), None)
    if dest_pcb:
        if not src_pcb:
            raise ValueError("Missing password callback value")
        dest_pcb.password = src_pcb.password

    return user_name
```

Please note that this is a direct translation of the Java code into Python. It might require some adjustments to work correctly in your specific use case, as it's hard to replicate all edge cases without knowing more about how you plan to use these classes.