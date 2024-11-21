class ClusterTimeGenerator:
    def __init__(self,
                 context: 'QueryContext',
                 meta_group_member: 'MetaGroupMember',
                 raw_data_query_plan: 'RawDataQueryPlan',
                 only_check_local_data: bool):
        self.query_plan = raw_data_query_plan
        self.reader_factory = ClusterReaderFactory(meta_group_member)
        try:
            reader_factory.sync_meta_group()
            if only_check_local_data:
                whether_has_local_reader(query_plan.get_expression(), meta_group_member, query_plan.is_ascending())
            else:
                construct_node(query_plan.get_expression())
        except (IOException | CheckConsistencyException) as e:
            raise StorageEngineException(e)

    @TestOnly
    def __init__(self,
                 context: 'QueryContext',
                 meta_group_member: 'MetaGroupMember',
                 cluster_reader_factory: ClusterReaderFactory,
                 raw_data_query_plan: 'RawDataQueryPlan',
                 only_check_local_data: bool):
        self.query_plan = raw_data_query_plan
        self.reader_factory = cluster_reader_factory
        try:
            reader_factory.sync_meta_group()
            if only_check_local_data:
                whether_has_local_reader(query_plan.get_expression(), meta_group_member, query_plan.is_ascending())
            else:
                construct_node(query_plan.get_expression())
        except (IOException | CheckConsistencyException) as e:
            raise StorageEngineException(e)

    def generate_new_batch_reader(self, expression: 'SingleSeriesExpression') -> IBatchReader:
        filter = expression.get_filter()
        time_filter = get_time_filter(filter)
        path = expression.get_series_path()
        data_type; merge_reader
        try:
            data_type = IoTDB.meta_manager.get_series_type(path)
            merge_reader = self.reader_factory.get_series_reader(
                path,
                query_plan.get_all_measurements_in_device(path.device),
                data_type,
                time_filter,
                filter,
                context,
                query_plan.is_ascending()
            )
        except Exception as e:
            raise IOException(e)

        return merge_reader

    def is_has_local_reader(self) -> bool:
        return self.has_local_reader

    def __str__(self):
        return super().__str__() + f", has local reader: {self.has_local_reader}"

    def whether_has_local_data_group(self, expression: 'IExpression', meta_group_member: 'MetaGroupMember', is_ascending: bool) -> None:
        self.has_local_reader = False
        construct_node(expression, meta_group_member, is_ascending)

    def construct_node(self, expression: 'IExpression', meta_group_member: 'MetaGroupMember', is_ascending: bool) -> Node:
        if isinstance(expression, SingleSeriesExpression):
            check_has_local_reader(expression, meta_group_member)
            return LeafNode(None)
        else:
            left_child = self.construct_node(((IBinaryExpression) expression).get_left(), meta_group_member, is_ascending)
            right_child = self.construct_node(((IBinaryExpression) expression).get_right(), meta_group_member, is_ascending)

            if isinstance(expression, IBinaryExpression):
                return OrNode(left_child, right_child, is_ascending)
            elif isinstance(expression, AndNode):
                return AndNode(left_child, right_child, is_ascending)
        raise UnSupportedDataTypeException(f"Unsupported ExpressionType when construct OperatorNode: {expression.type}")

    def check_has_local_reader(self, expression: 'SingleSeriesExpression', meta_group_member: 'MetaGroupMember') -> None:
        filter = expression.get_filter()
        time_filter = get_time_filter(filter)
        path = expression.get_series_path()
        data_type
        try:
            data_type = IoTDB.meta_manager.get_series_type(path)

            partition_groups = meta_group_member.route_filter(None, path)
            for partition_group in partition_groups:
                if partition_group.contains(meta_group_member.this_node):
                    data_group_member = meta_group_member.local_data_member(
                        partition_group.header,
                        f"Query: {path}, time filter: None, queryId: {context.query_id}"
                    )

                    point_reader = self.reader_factory.get_series_point_reader(
                        path,
                        query_plan.all_measurements_in_device(path.device),
                        data_type,
                        time_filter,
                        filter,
                        context,
                        data_group_member,
                        query_plan.is_ascending(),
                        None
                    )
                    if point_reader.has_next_time_value_pair():
                        self.has_local_reader = True
                        self.end_point = None
                        point_reader.close()
                        break
                    point_reader.close()

                elif not self.end_point:
                    self.end_point = QueryDataSet.EndPoint(
                        partition_group.header.node.client_ip,
                        partition_group.header.node.client_port
                    )
        except Exception as e:
            raise IOException(e)

    def get_time_filter(self, filter: 'Filter') -> Filter:
        # implement this method to return the time filter based on the given filter
        pass

class ClusterReaderFactory:
    def __init__(self, meta_group_member: 'MetaGroupMember'):
        self.meta_group_member = meta_group_member

    def sync_meta_group(self) -> None:
        # implement this method to synchronize the meta group with IoTDB
        pass

    def get_series_reader(self,
                           path: PartialPath,
                           measurements_in_device: List[str],
                           data_type: TSDataType,
                           time_filter: Filter,
                           filter: Filter,
                           context: 'QueryContext',
                           is_ascending: bool) -> IBatchReader:
        # implement this method to return a series reader based on the given parameters
        pass

    def get_series_point_reader(self,
                                 path: PartialPath,
                                 measurements_in_device: List[str],
                                 data_type: TSDataType,
                                 time_filter: Filter,
                                 filter: Filter,
                                 context: 'QueryContext',
                                 data_group_member: DataGroupMember,
                                 is_ascending: bool) -> IPointReader:
        # implement this method to return a series point reader based on the given parameters
        pass

class QueryContext:
    def __init__(self):
        self.query_id = 0

    @property
    def query_id(self) -> int:
        return self._query_id

    @query_id.setter
    def query_id(self, value: int) -> None:
        self._query_id = value

class MetaGroupMember:
    pass

class DataGroupMember:
    pass

class PartitionGroup:
    pass

class LeafNode(Node):
    def __init__(self, left_child: 'Node'):
        super().__init__()
        self.left_child = left_child

class OrNode(Node):
    def __init__(self, left_child: 'Node', right_child: 'Node', is_ascending: bool):
        super().__init__()
        self.left_child = left_child
        self.right_child = right_child
        self.is_ascending = is_ascending

class AndNode(Node):
    def __init__(self, left_child: 'Node', right_child: 'Node', is_ascending: bool):
        super().__init__()
        self.left_child = left_child
        self.right_child = right_child
        self.is_ascending = is_ascending

class SingleSeriesExpression:
    pass

class IPointReader:
    def has_next_time_value_pair(self) -> bool:
        # implement this method to check if there are more time value pairs available in the reader
        pass

    def close(self) -> None:
        # implement this method to close the point reader
        pass

class IBatchReader:
    pass

class StorageEngineException(Exception):
    pass

class UnSupportedDataTypeException(Exception):
    pass
