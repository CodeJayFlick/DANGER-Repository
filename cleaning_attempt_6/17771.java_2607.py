class FakedInnerSpaceCompactionTask:
    def __init__(self,
                logical_storage_group_name: str,
                virtual_storage_group_name: str,
                time_partition: int,
                ts_file_manager,  # assuming this has been defined elsewhere in your program
                ts_file_resource_list,  # assuming this has been defined elsewhere in your program
                selected_ts_file_resources: list,  # assuming this is a list of TsFileResource objects
                sequence: bool,
                current_task_num: int):
        super().__init__(logical_storage_group_name,
                         virtual_storage_group_name,
                         time_partition,
                         ts_file_manager,
                         ts_file_resource_list,
                         selected_ts_file_resources,
                         sequence,
                         current_task_num)

    def do_compaction(self) -> None:
        name = TsFileNameGenerator.get_ts_filename(selected_ts_file_resources[0].ts_file.name)
        new_name = TsFileNameGenerator.generate_new_ts_filename(
            name.time, 
            name.version, 
            name.inner_compaction_cnt + 1, 
            name.cross_compaction_cnt
        )
        target_ts_file_resource = FakedTsFileResource(0, new_name)
        target_file_size = 0
        for resource in selected_ts_file_resources:
            target_file_size += resource.ts_file_size
        target_ts_file_resource.ts_file_size = target_file_size
        self.ts_file_resource_list.insert_before(selected_ts_file_resources[0], target_ts_file_resource)
        for ts_file_resource in selected_ts_file_resources:
            self.ts_file_resource_list.remove(ts_file_resource)

    def equals_other_task(self, other_task: 'AbstractCompactionTask') -> bool:
        return False

    def check_valid_and_set_merging(self) -> bool:
        for resource in selected_ts_file_resources:
            if resource.is_merging or not resource.is_closed():
                return False
        return True


# assuming these classes have been defined elsewhere in your program
class TsFileNameGenerator:
    @staticmethod
    def get_ts_filename(ts_file_name: str):
        # implement this method as needed

    @staticmethod
    def generate_new_ts_filename(time, version, inner_compaction_cnt, cross_compaction_cnt) -> str:
        # implement this method as needed


class FakedTsFileResource:
    def __init__(self, ts_file_size: int, name: str):
        self.ts_file_size = ts_file_size
        self.name = name

    @property
    def is_merging(self) -> bool:
        return False  # implement this method as needed

    @property
    def is_closed(self) -> bool:
        return True  # implement this methods as needed


class TsFileResourceList(list):
    def insert_before(self, before: 'TsFileResource', after: 'TsFileResource') -> None:
        self.insert(0 if not before else -1, [after])

    def remove(self, ts_file_resource: 'TsFileResource') -> None:
        super().remove(ts_file_resource)
