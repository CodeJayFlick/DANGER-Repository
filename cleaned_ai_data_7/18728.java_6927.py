import logging

class CognitoIdentityFilter:
    COGNITO_IDENTITY_ATTRIBUTE = "com.amazonaws.serverless.cognitoId"

    def __init__(self):
        self.log = logging.getLogger(__name__)

    def init(self, filter_config):
        # nothing to do in init
        pass


    def do_filter(self, servlet_request, servlet_response, filter_chain):
        api_gw_context = servlet_request.get(RequestReader.API_GATEWAY_CONTEXT_PROPERTY)
        if api_gw_context is None:
            self.log.warning("API Gateway context is null")
            filter_chain.do_filter(servlet_request, servlet_response)
            return

        if not isinstance(api_gw_context, AwsProxyRequestContext):
            self.log.warning("API Gateway context object is not of valid type")
            filter_chain.do_filter(servlet_request, servlet_response)

        ctx = api_gw_context
        if ctx.identity is None:
            self.log.warning("Identity context is null")
            filter_chain.do_filter(servlet_request, servlet_response)
        
        cognito_identity_id = ctx.identity.cognito_identity_id
        if cognito_identity_id is None or ''.join(cognito_identity_id.split()).strip() == '':
            self.log.warning("Cognito identity id in request is null")

        servlet_request[CognitoIdentityFilter.COGNITO_IDENTITY_ATTRIBUTE] = cognito_identity_id
        filter_chain.do_filter(servlet_request, servlet_response)


    def destroy(self):
        # nothing to do in destroy
        pass

