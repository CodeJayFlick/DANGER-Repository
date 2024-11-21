class AwsProxyServletContextSupplier:
    def __init__(self):
        self.current_request = None

    def get(self) -> dict:
        return self.get_servlet_context()

    def get_servlet_context(self) -> dict:
        if not self.current_request:
            raise Exception("Could not find servlet request in context")

        ctx = self.current_request.environ['wsgiorgoriginaluri']
        return ctx
