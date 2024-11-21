import logging

class AbstractInnerSpaceCompactionTask:
    def __init__(self,
                 storage_group_name: str,
                 time_partition: int,
                 current_task_num: int,
                 sequence: bool,
                 selected_ts_file_resource_list: list):
        self.selected_ts_file_resource_list = selected_ts_file_resource_list
        self.sequence = sequence
        self.collect_selected_files_info()

    def collect_selected_files_info(self):
        self.selected_file_size = 0
        self.sum_of_compaction_count = 0
        self.max_file_version = -1
        self.max_compaction_count = -1

        if not self.selected_ts_file_resource_list:
            return

        for resource in self.selected_ts_file_resource_list:
            try:
                self.selected_file_size += resource.ts_file_size
                file_name = TsFileNameGenerator.get_ts_file_name(resource.ts_file.name)
                self.sum_of_compaction_count += file_name.inner_compaction_cnt
                if file_name.inner_compaction_cnt > self.max_compaction_count:
                    self.max_compaction_count = file_name.inner_compaction_cnt

                if file_name.version > self.max_file_version:
                    self.max_file_version = file_name.version
            except Exception as e:
                logging.warning(f"Fail to get the tsfile name of {resource.ts_file}, error: {e}")

    @property
    def selected_ts_file_resource_list(self):
        return self._selected_ts_file_resource_list

    @property
    def sequence(self):
        return self._sequence

    @property
    def selected_file_size(self):
        return self._selected_file_size

    @property
    def sum_of_compaction_count(self):
        return self._sum_of_compaction_count

    @property
    def max_file_version(self):
        return self._max_file_version

    @property
    def max_compaction_count(self):
        return self._max_compaction_count

    def check_valid_and_set_merging(self):
        for resource in self.selected_ts_file_resource_list:
            if not (resource.is_closed() and resource.ts_file.exists()):
                return False

        for resource in self.selected_ts_file_resource_list:
            resource.set_merging(True)

        return True

    def __str__(self):
        return f"{self.full_storage_group_name}-{self.time_partition} task file num is {len(self.selected_ts_file_resource_list)}, total compaction count is {self.sum_of_compaction_count}"
