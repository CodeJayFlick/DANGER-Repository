Here is the translation of the given Java code into Python:

```Python
import logging
from typing import List, Dict

class CrossSpaceMergeTask:
    def __init__(self,
                 seq_files: List['TsFileResource'],
                 unseq_files: List['TsFileResource'],
                 storage_group_sys_dir: str,
                 callback: 'MergeCallback',
                 task_name: str,
                 full_merge: bool,
                 storage_group_name: str):
        self.resource = CrossSpaceMergeResource(seq_files, unseq_files)
        self.storage_group_sys_dir = storage_group_sys_dir
        self.callback = callback
        self.task_name = task_name
        self.full_merge = full_merge
        self.concurrent_merge_series_num = 1
        self.storage_group_name = storage_group_name

    def do_merge(self) -> None:
        if not self.resource.get_seq_files():
            logging.info("{} no sequence file to merge into, so will abort task.".format(self.task_name))
            self.abort()
            return

        if logging.isinfoenabled():
            logging.info("{}. starts to merge seq files {}, unseq files {}".format(
                self.task_name,
                ', '.join([str(file) for file in self.resource.get_seq_files()]),
                ', '.join([str(file) for file in self.resource.get_unseq_files()])
            ))

        start_time = int(time.time())
        total_file_size = sum([file.size() for file in self.resource.get_seq_files()] + [file.size() for file in self.resource.get_unseq_files()])
        merge_logger = MergeLogger(self.storage_group_sys_dir)

        measurement_schema_map: Dict[PartialPath, 'IMeasurementSchema'] = IoTDB.meta_manager.get_all_measurement_schema_by_prefix(PartialPath(self.storage_group_name))
        unmerged_series: List[PartialPath] = list(measurement_schema_map.keys())
        self.resource.set_measurement_schema_map(measurement_schema_map)

        merge_logger.log_files(self.resource)
        merge_logger.log_merge_start()

        chunk_task = MergeMultiChunkTask(
            self.merge_context,
            self.task_name,
            merge_logger,
            self.resource,
            self.full_merge,
            unmerged_series,
            self.concurrent_merge_series_num,
            self.storage_group_name
        )
        self.states = States.MERGE_CHUNKS
        chunk_task.merge_series()
        if threading.current_thread().interrupted():
            logging.info("Merge task {} aborted".format(self.task_name))
            self.abort()
            return

        file_task = MergeFileTask(
            self.task_name,
            self.merge_context,
            merge_logger,
            self.resource,
            self.resource.get_seq_files()
        )
        self.states = States.MERGE_FILES
        chunk_task = None
        file_task.merge_files()
        if threading.current_thread().interrupted():
            logging.info("Merge task {} aborted".format(self.task_name))
            self.abort()
            return

        self.states = States.CLEAN_UP
        file_task = None
        self.clean_up(True)
        elapsed_time = int(time.time()) - start_time
        byte_rate = total_file_size / (elapsed_time * 1024 * 1024)
        series_rate = len(unmerged_series) / elapsed_time
        chunk_rate = self.merge_context.get_total_chunk_written() / elapsed_time
        file_rate = (len(self.resource.get_seq_files()) + len(self.resource.get_unseq_files())) / elapsed_time
        pt_rate = self.merge_context.get_total_point_written() / elapsed_time
        logging.info(
            "{} ends after {}s, byteRate: {:.2f}MB/s, seriesRate {}/s, chunkRate: {}/s, fileRate: {}/s, ptRate: {}/s".format(
                self.task_name,
                elapsed_time,
                byte_rate,
                series_rate,
                chunk_rate,
                file_rate,
                pt_rate
            )
        )

    def clean_up(self, execute_callback: bool) -> None:
        logging.info("{} is cleaning up".format(self.task_name))

        self.resource.clear()
        self.merge_context.clear()

        if self.merge_logger:
            self.merge_logger.close()

        for seq_file in self.resource.get_seq_files():
            merge_file = File(seq_file.ts_file_path + ".merge")
            merge_file.delete()
            seq_file.set_merging(False)

        for unseq_file in self.resource.get_unseq_files():
            unseq_file.set_merging(False)

        log_file = File(self.storage_group_sys_dir, "merge.log")

        if execute_callback:
            # make sure merge.log is not deleted until unseqFiles are cleared so that when system reboots,
            # the undeleted files can be deleted again
            self.callback.call(
                list(self.resource.get_seq_files()),
                list(self.resource.get_unseq_files()),
                log_file
            )
        else:
            log_file.delete()

    @property
    def storage_group_name(self) -> str:
        return self.storage_group_name

    @property
    def progress(self) -> str:
        if self.states == States.ABORTED:
            return "Aborted"
        elif self.states == States.CLEAN_UP:
            return "Cleaning up"
        elif self.states == States.MERGE_FILES:
            return f"Merging files: {file_task.progress}"
        elif self.states == States.MERGE_CHUNKS:
            return f"Merging series: {chunk_task.progress}"
        else:
            return "Just started"

    @property
    def task_name(self) -> str:
        return self.task_name

class CrossSpaceMergeResource:
    # ... same as Java code ...

class MergeLogger:
    # ... same as Java code ...

class TsFileResource:
    # ... same as Java code ...
```

Note that this translation is not a direct conversion from the given Java code to Python, but rather an interpretation of how the equivalent functionality could be implemented in Python.