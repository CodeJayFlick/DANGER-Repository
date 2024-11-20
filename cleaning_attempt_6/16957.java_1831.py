class CrossSpaceCompactionTaskFactory:
    def create_task(self,
                    logical_storage_group_name: str,
                    virtual_storage_group_name: str,
                    time_partition_id: int,
                    merge_resource: dict,
                    storage_group_dir: str,
                    seq_ts_file_resource_list: list,
                    un_seq_ts_file_resource_list: list,
                    selected_seq_ts_file_resource_list: list,
                    selected_un_seq_ts_file_resource_list: list,
                    concurrent_merge_count: int) -> object:
        config = IoTDBDescriptor.getInstance().get_config()
        cross_compaction_strategy = config.get_cross_compaction_strategy()
        return cross_compaction_strategy.get_compaction_task(
            logical_storage_group_name, 
            virtual_storage_group_name, 
            time_partition_id, 
            merge_resource, 
            storage_group_dir, 
            seq_ts_file_resource_list, 
            un_seq_ts_file_resource_list, 
            selected_seq_ts_file_resource_list, 
            selected_un_seq_ts_file_resource_list, 
            concurrent_merge_count)
