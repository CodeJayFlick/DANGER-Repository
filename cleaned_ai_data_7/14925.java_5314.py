import logging

class InitContext:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def lookup(self, service_name: str) -> object:
        if service_name == "jndi/serviceA":
            self.logger.info("Looking up service A and creating new service for A")
            return ServiceImpl("jndi/serviceA")
        elif service_name == "jndi/serviceB":
            self.logger.info("Looking up service B and creating new service for B")
            return ServiceImpl("jndi/serviceB")
        else:
            return None


class ServiceImpl:
    def __init__(self, name: str):
        pass
