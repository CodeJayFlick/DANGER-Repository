Here is the translation of the Java code to Python:

```Python
import logging
from typing import Callable

class AwsHttpApiV2SecurityContext:
    AUTH_SCHEME_JWT = "JWT"

    def __init__(self, lambda_ctx: dict, request: dict):
        self.lambda_context = lambda_ctx
        self.event = request

    @property
    def get_authentication_scheme(self) -> str | None:
        if not self.event.get("requestContext", {}).get("authorizer"):
            return None
        if self.event["requestContext"]["authorizer"].get("jwtAuthorizer") and \
           self.event["requestContext"]["authorizer"]["jwtAuthorizer"].get("isJwt"):
            return self.AUTH_SCHEME_JWT
        return None

    def get_user_principal(self) -> Callable | None:
        auth_value = self.event.get("headers", {}).get("Authorization")
        if not auth_value or not self.get_authentication_scheme:
            return None
        parts = auth_value.split(".")[1:]
        if len(parts) != 3:
            logging.warning(f"Could not parse JWT token for requestId: {self.lambda_context['requestId']}")
            return None
        decoded_body = base64.b64decode(parts[1]).decode("utf-8")
        try:
            parsed_body = json.loads(decoded_body)
            if not isinstance(parsed_body, dict) or "sub" not in parsed_body:
                logging.debug(f"Could not find 'sub' field in JWT body for requestId: {self.lambda_context['requestId']}")
                return None
            subject = parsed_body["sub"]
            return lambda: subject
        except json.JSONDecodeError as e:
            logging.error(f"Error while attempting to parse JWT body for requestId: {self.lambda_context['requestId']}", e)
            return None

    def is_user_in_role(self, role: str) -> bool:
        if not self.get_authentication_scheme:
            return False
        return (role in self.event["requestContext"]["authorizer"].get("jwtAuthorizer", {}).get("scopes", []) or 
               role in [key for key in self.event["requestContext"]["authorizer"].get("jwtAuthorizer", {}).get("claims", {})])

    def is_secure(self) -> bool:
        return self.get_authentication_scheme is not None
```

Note that I used the `json` and `base64` modules from Python's standard library, as well as a logging module. The `AwsHttpApiV2SecurityContext` class has been translated to Python using similar logic to the original Java code.