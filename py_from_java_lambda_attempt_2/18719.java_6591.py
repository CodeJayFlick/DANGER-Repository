Here is the equivalent Python code for the given Java file:

```Python
import logging

class CognitoIdentityFilter:
    COGNITO_IDENTITY_ATTRIBUTE = "com.amazonaws.serverless.cognitoId"

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def init(self, filter_config):
        # nothing to do in init
        pass


    def do_filter(self, servlet_request, servlet_response, filter_chain):
        api_gw_context = servlet_request.get("API_GATEWAY_CONTEXT_PROPERTY")
        
        if api_gw_context is None:
            self.logger.warning("API Gateway context is null")
            filter_chain.do_filter(servlet_request, servlet_response)
            
        elif not isinstance(api_gw_context, AwsProxyRequestContext):
            self.logger.warning("API Gateway context object is not of valid type")
            filter_chain.do_filter(servlet_request, servlet_response)

        ctx = api_gw_context if isinstance(api_gw_context, AwsProxyRequestContext) else None
        if ctx is None:
            self.logger.warning("Identity context is null")
            filter_chain.do_filter(servlet_request, servlet_response)
            
        elif ctx.identity is None:
            self.logger.warning("Identity context is null")
            filter_chain.do_filter(servlet_request, servlet_response)

        cognito_identity_id = ctx.identity.get_cognito_identity_id() if ctx.identity else None
        if cognito_identity_id is None or ''.join(cognito_identity_id.split()).lower() == '':
            self.logger.warning("Cognito identity id in request is null")
            
        servlet_request[CognitoIdentityFilter.COGNITO_IDENTITY_ATTRIBUTE] = cognito_identity_id
        filter_chain.do_filter(servlet_request, servlet_response)


    def destroy(self):
        # nothing to do in destroy
        pass

class AwsProxyRequestContext:
    def get_cognito_identity_id(self):
        return None  # implement this method as per your requirement


# Usage example:

filter = CognitoIdentityFilter()
request = {'API_GATEWAY_CONTEXT_PROPERTY': 'some_context'}
response = {}
chain = lambda x, y: print(f"Filtered request {x} and response {y}")

filter.do_filter(request, response, chain)
```

Please note that this Python code is not a direct translation of the Java code. It's an equivalent implementation in Python with some differences due to language-specific features and best practices.