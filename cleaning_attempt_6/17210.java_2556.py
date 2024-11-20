class IPlanExecutor:
    def process_query(self, query_plan: 'PhysicalPlan', context: 'QueryContext') -> 'QueryDataSet':
        # Your implementation here
        pass

    def process_non_query(self, plan: 'PhysicalPlan') -> bool:
        # Your implementation here
        return False  # Default value if not implemented

    def update(self, path: 'PartialPath', start_time: int, end_time: int, value: str) -> None:
        # Your implementation here
        pass

    def delete(self, delete_plan: 'DeletePlan') -> None:
        # Your implementation here
        pass

    def delete(self, path: 'PartialPath', start_time: int, end_time: int, plan_index: int, partition_filter: 'TimePartitionFilter' = None) -> None:
        # Your implementation here
        pass

    def insert(self, insert_row_plan: 'InsertRowPlan') -> None:
        # Your implementation here
        pass

    def insert(self, insert_rows_plan: 'InsertRowsPlan') -> None:
        # Your implementation here
        pass

    def insert(self, insert_rows_of_one_device_plan: 'InsertRowsOfOneDevicePlan') -> None:
        # Your implementation here
        pass

    def insert_tablet(self, insert_tablet_plan: 'InsertTabletPlan') -> None:
        # Your implementation here
        pass

    def insert_multi_tablet(self, insert_multi_tablet_plan: 'InsertMultiTabletPlan') -> None:
        # Your implementation here
        pass
