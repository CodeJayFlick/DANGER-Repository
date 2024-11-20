class SynchronizedHandler:
    def __init__(self, client):
        self.client = client

    def invoke(self, proxy, method_name, args):
        try:
            with self.client as client:
                return getattr(client, method_name)(*args)
        except Exception as e:
            if isinstance(e, TException):
                raise e
            else:
                raise TException(f"Error in calling method {method_name}", e)

import thrift.TService

class TSIService(TService.Iface):
    pass

# Usage example:

client = TSIService()
handler = SynchronizedHandler(client)
