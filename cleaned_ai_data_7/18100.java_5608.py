import logging
from docker import DockerClient
from docker.types import ServicePort
from unittest.mock import patch

class ClusterSessionSimpleIT:
    def __init__(self):
        self.node1_logger = logging.getLogger("iotdb-server_1")
        self.node2_logger = logging.getLogger("iotdb-server_2")
        self.node3_logger = logging.getLogger("iotdb-server_3")

        # Initialize session
        self.session = None

    @patch('docker.DockerClient')
    def test_session_cluster(self, docker_client):
        environment = DockerComposeContainer(
            '3nodes',
            path='src/test/resources/3nodes/docker-compose.yaml'
        )
        environment.start()

        service1_port = environment.get_service_port("iotdb-server_1", 6667)
        service2_port = environment.get_service_port("iotdb-server_2", 6667)
        service3_port = environment.get_service_port("iotdb-server_3", 6667)

        string_list = ["localhost:{}".format(port) for port in [service1_port, service2_port, service3_port]]
        self.session = Session(string_list, "root", "root")
        self.session.open()
        self.session.set_storage_group("root.sg1")
        self.session.create_timeseries(
            "root.sg1.d1.s1",
            TSDataType.INT64,
            TSEncoding.RLE,
            CompressionType.SNAPPY
        )
        self.session.create_timeseries(
            "root.sg1.d2.s1",
            TSDataType.INT64,
            TSEncoding.RLE,
            CompressionType.SNAPPY
        )

    def get_container(self):
        return environment

if __name__ == "__main__":
    it = ClusterSessionSimpleIT()
    it.test_session_cluster()
