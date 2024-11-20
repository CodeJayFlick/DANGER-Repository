Here is the equivalent Python code:

```Python
import logging
from testcontainers.compose import DockerCompose
from testcontainers.wait import wait_for


class AbstractThreeNodeClusterIT:
    node1_logger = logging.getLogger("iotdb-server_1")
    node2_logger = logging.getLogger("iotdb-server_2")
    node3_logger = logging.getLogger("iotdb-server_3")

    @classmethod
    def setup(cls):
        cls.environment = DockerCompose(
            "3nodes",
            path="src/test/resources/3nodes/docker-compose.yaml"
        ).with_exposed_service("iotdb-server_1", 6667, wait_for.port())
        .with_log_consumer("iotdb-server_1", node1_logger)
        .with_exposed_service("iotdb-server_2", 6667, wait_for.port())
        .with_log_consumer("iotdb-server_2", node2_logger)
        .with_exposed_service("iotdb-server_3", 6667, wait_for.port())
        .with_log_consumer("iotdb-server_3", node3_logger)
        .with_local_compose(True)

    @classmethod
    def get_container(cls):
        return cls.environment

# Usage:
AbstractThreeNodeClusterIT.setup()
container = AbstractThreeNodeClusterIT.get_container()
```

Please note that Python does not have direct equivalent of Java's `@Rule` and `@ClassRule`. In the above code, I used a class method to set up the environment.