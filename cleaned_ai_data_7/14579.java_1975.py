import logging

class Server:
    def __init__(self, host: str, port: int, id: int):
        self.host = host
        self.port = port
        self.id = id

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @property
    def id(self) -> int:
        return self._id

    def serve(self, request):
        logging.info("Server ID {} associated to host: {}, and port {}. Processed request with value {}".format(
            self.id, self.host, self.port, request.value))

# Example usage:
if __name__ == "__main__":
    server = Server("example.com", 8080, 1)
    request = {"value": "Hello World"}
    server.serve(request)
