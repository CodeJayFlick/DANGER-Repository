Here is the translation of the Java code into Python:

```Python
import logging
from typing import List, Set, Dict

class MetaPuller:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.meta_group_member = None

    @classmethod
    def get_instance(cls) -> 'MetaPuller':
        if not hasattr(MetaPuller, '_instance'):
            MetaPuller._instance = MetaPuller()
        return MetaPuller._instance

    def init(self, meta_group_member: object):
        self.meta_group_member = meta_group_member

    def pull_measurement_schemas(
        self,
        partition_group: object,
        prefix_paths: List[object],
        results: List[object]
    ) -> None:
        if partition_group.contains(self.meta_group_member.get_this_node()):
            try:
                self.meta_group_member.sync_leader(None)
            except CheckConsistencyException as e:
                self.logger.warn("Failed to check consistency.", e)

            for prefix_path in prefix_paths:
                IoTDB.meta_manager.collect_measurement_schema(prefix_path, results)

        else:
            pull_schema_request = PullSchemaRequest()
            pull_schema_request.set_header(partition_group.get_header())
            pull_schema_request.set_prefix_paths([str(path) for path in prefix_paths])

            for node in partition_group:
                if self.pull_measurement_schemas(node, pull_schema_request, results):
                    break

    def try_pull_time_series_schemas(
        self,
        node: object,
        request: PullSchemaRequest,
        timeseries_schemas: List[object]
    ) -> bool:
        schemas = None
        try:
            schemas = self.pull_time_series_schemas(node, request)
        except (IOException, TException) as e:
            self.logger.error(
                "{}: Cannot pull time series schema of {} and other {} paths from {}".format(
                    self.meta_group_member.get_name(),
                    request.get_prefix_paths()[0],
                    len(request.get_prefix_paths()) - 1,
                    node
                ),
                e
            )
        except InterruptedException as e:
            Thread.currentThread().interrupt()
            self.logger.error(
                "{}: Cannot pull time series schema of {} and other {} paths from {}".format(
                    self.meta_group_member.get_name(),
                    request.get_prefix_paths()[0],
                    len(request.get_prefix_paths()) - 1,
                    node
                ),
                e
            )

        if schemas is not None:
            for schema in schemas:
                SchemaUtils.cache_timeseries_schema(schema)

            return True

        return False

    def pull_time_series_schemas(
        self, node: object, request: PullSchemaRequest
    ) -> List[object]:
        if ClusterDescriptor.get_instance().get_config().is_use_async_server():
            client = AsyncDataClient(self.meta_group_member.get_client_provider(), node)
            schemas = SyncClientAdaptor.pull_timeseries_schema(client, request)

        else:
            try:
                sync_data_client = SyncDataClient(
                    self.meta_group_member.get_client_provider(),
                    node,
                    RaftServer.get_read_operation_timeout_ms()
                )
                pull_schema_resp = sync_data_client.pull_time_series_schema(request)
                buffer = pull_schema_resp.schema_bytes
                size = buffer.getvalue().get_int32(0)

                schemas = []
                for _ in range(size):
                    schema = TimeseriesSchema.deserialize_from(buffer)
                    schemas.append(schema)

            except (IOException, TException) as e:
                self.logger.error(
                    "{}: Cannot pull time series schema of {} and other {} paths from {}".format(
                        self.meta_group_member.get_name(),
                        request.get_prefix_paths()[0],
                        len(request.get_prefix_paths()) - 1,
                        node
                    ),
                    e
                )

        return schemas

class PullSchemaRequest:
    def __init__(self):
        pass

    def set_header(self, header: object) -> None:
        self.header = header

    def set_prefix_paths(self, prefix_paths: List[object]) -> None:
        self.prefix_paths = [str(path) for path in prefix_paths]

class PullSchemaResp:
    def __init__(self):
        pass

    @property
    def schema_bytes(self) -> object:
        return None

def main():
    meta_puller = MetaPuller.get_instance()
    # ... use the meta puller ...

if __name__ == "__main__":
    main()

```

Please note that Python does not support static initialization of variables like Java. The equivalent concept in Python is class-level attributes, which are initialized when an instance of a class is created.

The `MetaPuller` class has been modified to use the logging module instead of its own logger.