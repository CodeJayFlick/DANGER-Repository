import os
import logging


class MergeLogger:
    MERGE_LOG_NAME = "merge.log"

    STR_SEQ_FILES = "seqFiles"
    STR_UNSEQ_FILES = "unseqFiles"
    STR_TIMESERIES = "timeseries"
    STR_START = "start"
    STR_END = "end"
    STR_ALL_TS_END = "all ts end"
    STR_MERGE_START = "merge start"
    STR_MERGE_END = "merge end"

    def __init__(self, storage_group_dir):
        self.log_stream = open(os.path.join(storage_group_dir, MergeLogger.MERGE_LOG_NAME), 'a', encoding='utf-8')

    def close(self):
        self.log_stream.close()

    def log_ts_start(self, paths):
        self.log_stream.write(f"{MergeLogger.STR_START}\n")
        for path in paths:
            self.log_stream.write(f"  {path}\n")
        self.log_stream.flush()

    def log_file_position(self, file_path):
        self.log_stream.write(f"{file_path} {os.path.getsize(file_path)}\n")
        self.log_stream.flush()

    def log_ts_end(self):
        self.log_stream.write(MergeLogger.STR_END + "\n")
        self.log_stream.flush()

    def log_all_ts_end(self):
        self.log_stream.write(MergeLogger.STR_ALL_TS_END + "\n")
        self.log_stream.flush()

    def log_file_merge_start(self, file_path, position):
        self.log_stream.write(f"{file_path} {position}\n")
        self.log_stream.flush()

    def log_file_merge_end(self):
        self.log_stream.write(MergeLogger.STR_END + "\n")
        self.log_stream.flush()

    def log_merge_end(self):
        self.log_stream.write(MergeLogger.STR_MERGE_END + "\n")
        self.log_stream.flush()

    def log_files(self, resource):
        self.log_seq_files(resource.get_seq_files())
        self.log_unseq_files(resource.get_unseq_files())

    def log_seq_files(self, seq_files):
        self.log_stream.write(f"{MergeLogger.STR_SEQ_FILES}\n")
        for ts_file_resource in seq_files:
            self.log_stream.write(f"  {ts_file_resource.ts_file.path}\n")
        self.log_stream.flush()

    def log_unseq_files(self, unseq_files):
        self.log_stream.write(f"{MergeLogger.STR_UNSEQ_FILES}\n")
        for ts_file_resource in unseq_files:
            self.log_stream.write(f"  {ts_file_resource.ts_file.path}\n")
        self.log_stream.flush()

    def log_merge_start(self):
        self.log_stream.write(MergeLogger.STR_MERGE_START + "\n")
        self.log_stream.flush()

    @staticmethod
    def find_cross_space_compaction_logs(directory):
        time_partition_dir = os.path.join(directory)
        if os.path.exists(time_partition_dir):
            return [os.path.join(time_partition_dir, name) for name in os.listdir(time_partition_dir) if name.endswith(MergeLogger.MERGE_LOG_NAME)]
        else:
            return []
