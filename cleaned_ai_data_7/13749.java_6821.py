import logging

class ServiceAmbassador:
    def do_remote_function(self, value):
        # implement your remote function here
        pass


class Client:
    def __init__(self):
        self.service_ambassador = ServiceAmbassador()

    def use_service(self, value: int) -> int:
        result = self.service_ambassador.do_remote_function(value)
        logging.info("Service result: %s", str(result))
        return result
