Here is the translation of the Java code into Python:

```Python
class AwsProxySecurityContext:
    AUTH_SCHEME_CUSTOM = "CUSTOM_AUTHORIZER"
    AUTH_SCHEME_COGNITO_POOL = "COGNITO_USER_POOL"
    AUTH_SCHEME_AWS_IAM = "AWS_IAM"

    ALB_ACCESS_TOKEN_HEADER = "x-amzn-oidc-accesstoken"
    ALB_IDENTITY_HEADER = "x-amzn-oidc-identity"


    def __init__(self, lambda_context: 'Context', event: 'AwsProxyRequest'):
        self.lambda_context = lambda_context
        self.event = event


    @property
    def lambda_context(self):
        return self._lambda_context

    @lambda_context.setter
    def lambda_context(self, value):
        self._lambda_context = value


    @property
    def event(self):
        return self._event

    @event.setter
    def event(self, value):
        self._event = value


    def get_user_principal(self) -> 'Principal':
        if not self.get_authentication_scheme():
            return lambda: None

        if self.get_authentication_scheme() in [AwsProxySecurityContext.AUTH_SCHEME_CUSTOM,
                                                  AwsProxySecurityContext.AUTH_SCHEME_AWS_IAM]:
            return lambda: {
                event.request_source == "API_Gateway": event.request_context.authorizer.principal_id(),
                event.request_source == "ALB": event.multi_value_headers.get(AwsProxySecurityContext.ALB_IDENTITY_HEADER)
            }()

        if self.get_authentication_scheme() == AwsProxySecurityContext.AUTH_SCHEME_COGNITO_POOL:
            return CognitoUserPoolPrincipal(event.request_context.authorizer.claims)

        raise RuntimeError("Cannot recognize authorization scheme in event")


    def is_user_in_role(self, role: str) -> bool:
        return role == self.event.request_context.identity.user_arn


    @property
    def is_secure(self):
        return bool(self.get_authentication_scheme())


    def get_authentication_scheme(self) -> str | None:
        if event.request_source == "API_Gateway":
            if event.request_context.authorizer and event.request_context.authorizer.claims and event.request_context.authorizer.claims.subject:
                return AwsProxySecurityContext.AUTH_SCHEME_COGNITO_POOL
            elif event.request_context.authorizer:
                return AwsProxySecurityContext.AUTH_SCHEME_CUSTOM
            elif event.request_context.identity.access_key:
                return AwsProxySecurityContext.AUTH_SCHEME_AWS_IAM

        if event.request_source == "ALB":
            if event.multi_value_headers.get(AwsProxySecuritySecurityContext.ALB_ACCESS_TOKEN_HEADER):
                return AwsProxySecurityContext.AUTH_SCHEME_CUSTOM

        return None


class CognitoUserPoolPrincipal:
    def __init__(self, claims: 'CognitoAuthorizerClaims'):
        self.claims = claims

    @property
    def name(self) -> str | None:
        return self.claims.subject

    @property
    def get_claims(self):
        return self.claims


class Principal:
    pass
```

Please note that this translation is not a direct copy-paste, but rather an interpretation of the Java code into Python.