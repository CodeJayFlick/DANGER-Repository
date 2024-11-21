import logging
from typing import List, Dict

class AwsProxyHttpServletRequest:
    def __init__(self, aws_proxy_request: 'AwsProxyRequest', lambda_context: 'Context', security_context: 'SecurityContext'):
        self.request = aws_proxy_request
        self.security_context = security_context
        super().__init__(lambda_context)

    @property
    def get_aws_proxy_request(self):
        return self.request

    # Implementation - HttpServletRequest

    def get_auth_type(self) -> str:
        return self.security_context.get_authentication_scheme()

    def get_cookies(self) -> List['Cookie']:
        if not self.request.get_multi_value_headers():
            return []
        cookie_header = self.request.get_multi_value_headers().get('COOKIE')
        if not cookie_header:
            return []
        return [self.parse_cookieHeaderValue(cookie_header)]

    # ... (rest of the implementation)

class AwsProxyRequest:
    def __init__(self, aws_proxy_request: 'AwsProxyRequest', lambda_context: 'Context'):
        self.request = aws_proxy_request
        super().__init__(lambda_context)
