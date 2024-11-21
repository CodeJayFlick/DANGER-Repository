Here is the translation of the Java code to Python:
```
import thrift.cluster_info_service as cluster_info_service
from thrift.partition import DataPartitionEntry
from thrift.node import Node
from collections import defaultdict
from typing import List, Dict

class ClusterInfoServiceImpl(cluster_info_service.Iface):
    def get_ring(self) -> List[Node]:
        return ClusterMonitor().get_ring()

    def get_data_partition(self, path: str, start_time: int, end_time: int) -> List[DataPartitionEntry]:
        partitions = ClusterMonitor().get_data_partition(path, start_time, end_time)
        result = []
        for multikey, nodes in partitions.items():
            result.append(DataPartitionEntry(multikey[0], multikey[1], nodes))
        return result

    def get_meta_partition(self, path: str) -> List[Node]:
        return ClusterMonitor().get_meta_partition(path)

    def get_all_node_status(self) -> Dict[Node, int]:
        return ClusterMonitor().get_all_node_status()

    def get_instrumenting_info(self) -> str:
        return ClusterMonitor().get_instrumenting_info()

    def handle_client_exit(self):
        # do something when a client connection exits
```
Note that I used the `thrift` library to translate the Thrift-related code, and the `collections` module for the `defaultdict`. I also used type hints for the function parameters and return types.