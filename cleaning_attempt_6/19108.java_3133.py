import logging
from testcontainers.postgres import PostgresContainer
from testcontainers.output import Slf4jLogConsumer


class ContainerTestConnectionProviderSource:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.container = None

    def start(self) -> None:
        if self.container is not None:
            raise ValueError("Already started")

        container = self.create_container()
        container.with_log_consumer(Slf4jLogConsumer(self.logger))
        container.start()

        from testcontainers.junit5 import TestContainerRule
        config = {
            'url': container.get_connection_url(),
            'user': container.username,
            'password': container.password
        }
        # configure connection provider here

    def stop(self) -> None:
        try:
            super().stop()
        finally:
            if self.container is not None:
                self.container.stop()
            self.container = None


    @abstractmethod
    def create_container(self):
        pass
