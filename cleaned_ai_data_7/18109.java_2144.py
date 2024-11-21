import logging
from testcontainers.mysql import MySQLContainer
from testcontainers.utils.wait import wait_for_db

class SingleNodeIT:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @classmethod
    def setup(cls):
        cls.dsl_container = (
            MySQLContainer("apache/iotdb:maven-development")
                .with_image_pull_policy("default")
                # mount another properties for changing parameters, e. g., open 5555 port (sync module)
                .with_file_system_bind(
                    "/path/to/src/test/resources/iotdb-engine.properties",
                    "/iotdb/conf/iotdb-engine.properties", "ro"
                )
                .with_file_system_bind(
                    "/path/to/src/test/resources/logback-container.xml",
                    "/iotdb/conf/logback.xml", "ro"
                )
                .with_log_consumer(logging.getLogger())
                .expose(6667)
                .wait_for(wait_for_db(timeout=60))
        )

    def init(self):
        self.rpc_port = self.dsl_container.get_ mapped_port(6667)
        self.sync_port = self.dsl_container.get_mapped_port(5555)

    @classmethod
    def teardown(cls):
        cls.dsl_container.stop()
