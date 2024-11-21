import asyncio
from typing import List, Set

class RemoteSeriesReaderByTimestamp:
    def __init__(self):
        self.batch_data = TestUtils.gen_batch_data(TSDataType.DOUBLE, 0, 100)
        self.failed_nodes: Set[Node] = set()
        self.prev_use_async_server = ClusterDescriptor.get_instance().get_config().is_use_async_server()

    async def get_values_in_timestamps(self, times: List[int], length: int) -> List[float]:
        results = []
        for i in range(length):
            while self.batch_data.has_current():
                current_time = self.batch_data.current_time()
                if current_time == times[i]:
                    results.append(self.batch_data.current_value())
                    self.batch_data.next()
                    break
                elif current_time > times[i]:
                    results.append(None)
                    break
        return [float(x) for x in results]

    async def query_single_series_by_timestamps(self, request: SingleSeriesQueryRequest):
        if any(node in self.failed_nodes for node in request.get_node()):
            raise TException("Node down.")
        
        await asyncio.create_task(request.on_complete(1L))

class MetaGroupMember:
    pass

class PartitionGroup:
    def __init__(self):
        self.nodes = []

    def add(self, node: Node):
        self.nodes.append(node)

class DataSourceInfo:
    def __init__(self, group: PartitionGroup, data_type: TSDataType, request: SingleSeriesQueryRequest, context: RemoteQueryContext, meta_group_member: MetaGroupMember, source_info: 'DataSourceInfo'):
        self.group = group
        self.data_type = data_type
        self.request = request
        self.context = context
        self.meta_group_member = meta_group_member
        self.source_info = source_info

    async def has_next_data_client(self) -> None:
        pass

class RemoteQueryContext:
    def __init__(self, query_id: int):
        self.query_id = query_id

    def get_query_id(self) -> int:
        return self.query_id

def test_remote_series_reader_by_timestamp():
    group = PartitionGroup()
    for i in range(3):
        node = TestUtils.get_node(i)
        group.add(node)

    request = SingleSeriesQueryRequest()
    context = RemoteQueryContext(1)

    try:
        source_info = DataSourceInfo(group, TSDataType.DOUBLE, request, context, MetaGroupMember(), None)
        await asyncio.create_task(source_info.has_next_data_client())

        reader = RemoteSeriesReaderByTimestamp()

        times = [i for i in range(100)]
        results = await reader.get_values_in_timestamps(times, len(times))
        for i in range(len(results)):
            assert results[i] == float(i)

        times[0] = 101
        result = await reader.get_values_in_timestamps([times[0]], 1)
        assert result is None

    finally:
        QueryResourceManager().end_query(context.query_id())

def test_failed_node():
    batch_data = TestUtils.gen_batch_data(TSDataType.DOUBLE, 0, 100)

    group = PartitionGroup()
    for i in range(3):
        node = TestUtils.get_node(i)
        group.add(node)

    request = SingleSeriesQueryRequest()
    context = RemoteQueryContext(1)

    try:
        source_info = DataSourceInfo(group, TSDataType.DOUBLE, request, context, MetaGroupMember(), None)
        await asyncio.create_task(source_info.has_next_data_client())

        reader = RemoteSeriesReaderByTimestamp()

        times = [i for i in range(50)]
        results = await reader.get_values_in_timestamps(times, len(times))
        for i in range(len(results)):
            assert results[i] == float(i)

        group.current_node = 0
        failed_nodes.add(group.current_node)
        times = [i + 50 for i in range(30)]
        results = await reader.get_values_in_timestamps(times, len(times))
        for i in range(len(results)):
            assert results[i] == float(i) + 50

        group.current_node = 1
        failed_nodes.add(group.current_node)
        times = [i + 80 for i in range(10)]
        results = await reader.get_values_in_timestamps(times, len(times))
        for i in range(len(results)):
            assert results[i] == float(i) + 80

        group.current_node = 2
        failed_nodes.add(group.current_node)
        try:
            times[0] = 90
            await reader.get_values_in_timestamps([times[0]], 1)
            fail()
        except Exception as e:
            assert str(e) == "no available client."

    finally:
        QueryResourceManager().end_query(context.query_id())

if __name__ == "__main__":
    test_remote_series_reader_by_timestamp()
    test_failed_node()

