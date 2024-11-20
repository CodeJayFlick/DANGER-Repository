Here is the translation of the given Java code into equivalent Python:

```Python
class BearerAuthenticationProvider:
    AUTH_TYPE_VALUE = "BEARER"

    def get_auth_type_value(self):
        return self.AUTH_TYPE_VALUE

    def build(self, config_supplier: callable) -> 'NessieAuthentication':
        token = config_supplier()
        return self.create(token)

    @staticmethod
    def create(token: str) -> 'HttpAuthentication':
        if not token:
            raise ValueError("Token must not be null for authentication type " + BearerAuthenticationProvider.AUTH_TYPE_VALUE)
        auth_header_value = f"Bearer {token}"
        return BearerAuthentication(auth_header_value)


class BearerAuthentication(HttpAuthentication):
    def __init__(self, auth_header_value: str):
        self.auth_header_value = auth_header_value

    def apply_to_http_client(self, client) -> None:
        client.register(lambda ctx: (ctx.put_header("Authorization", self.auth_header_value),))
```

Please note that Python does not have a direct equivalent to Java's `@Override` annotation. The method overriding is determined by the method name and its position in the class hierarchy.

Also, Python 3.x has type hints for function parameters which are similar to Java's generics but they do not provide any runtime checks or enforcement of types.