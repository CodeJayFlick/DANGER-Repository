class AwsProxyServletResponseSupplier:
    def __init__(self):
        self.current_request = None

    #-------------------------------------------------------------
    # Implementation - Factory
    #-------------------------------------------------------------

    def get(self) -> 'HttpServletResponse':
        return self.get_response()

    def get_response(self) -> 'HttpServletResponse':
        if not hasattr(self, '_response'):
            setattr(self, '_response', self.current_request[JERSEY_SERVLET_RESPONSE_PROPERTY])
        return getattr(self, '_response')
