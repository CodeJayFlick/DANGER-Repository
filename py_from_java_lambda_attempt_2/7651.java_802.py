Here is the translation of the given Java code into Python:

```Python
class AuthenticationModule:
    USERNAME_CALLBACK_PROMPT = "User ID"
    PASSWORD_CALLBACK_PROMPT = "Password"

    def authenticate(self, user_mgr: 'Ghidra server user manager', subject: 'unauthenticated user ID', callbacks: list) -> str:
        try:
            # Your authentication logic here
            pass
        except LoginException as e:
            raise LoginException("Error during login")
        except FailedLoginException as e:
            raise FailedLoginException("Authentication was unsuccessful")

    def get_authentication_callbacks(self):
        return []

    def anonymous_callbacks_allowed(self) -> bool:
        return True

    def is_name_callback_allowed(self) -> bool:
        return True

    @staticmethod
    def create_simple_name_password_callbacks(allow_user_to_specify_name: bool) -> list:
        pass_cb = PasswordCallback(PASSWORD_CALLBACK_PROMPT + ":", False)
        if allow_user_to_specify_name:
            name_cb = NameCallback(USERNAME_CALLBACK_PROMPT + ":")
            return [name_cb, pass_cb]
        else:
            return [pass_cb]

    @staticmethod
    def get_first_callback_of_type(callback_class: type, callback_array: list) -> object:
        if not callback_array:
            return None

        for cb in callback_array:
            if callback_class == cb.__class__:
                return cb

        return None


# Example usage:

auth_module = AuthenticationModule()
callbacks = auth_module.create_simple_name_password_callbacks(True)
print(auth_module.get_first_callback_of_type(NameCallback, callbacks))
```

Please note that this is a direct translation of the Java code into Python. The actual implementation may vary based on your specific requirements and use cases.