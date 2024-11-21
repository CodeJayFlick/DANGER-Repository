import logging
from collections import defaultdict
from queue import PriorityQueue
from threading import Thread

class SystemInfo:
    def __init__(self):
        self.config = IoTDBConfig()
        self.logger = logging.getLogger(__name__)
        self.total_storage_group_mem_cost = 0L
        self.rejected = False
        self.memory_size_for_write = self.config.get_allocate_memory_for_write()
        self.reported_storage_group_mem_cost_map = defaultdict(long)
        self.flushing_mem_tables_cost = 0L

    def report_storage_group_status(self, storage_group_info: StorageGroupInfo, ts_file_processor: TsFileProcessor) -> bool:
        delta = storage_group_info.mem_cost - self.reported_storage_group_mem_cost_map[storage_group_info]
        self.total_storage_group_mem_cost += delta
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("Report Storage Group Status to the system. After adding {}, current sg mem cost is {}.".format(delta, self.total_storage_group_mem_cost))
        self.reported_storage_group_mem_cost_map[storage_group_info] = storage_group_info.mem_cost
        storage_group_info.set_last_reported_size(storage_group_info.mem_cost)
        if self.total_storage_group_mem_cost < self.config.get_flush_proportion() * self.memory_size_for_write:
            return True
        elif self.total_storage_group_mem_cost >= self.config.get_flush_proportion() * self.memory_size_for_write and self.total_storage_group_mem_cost < self.config.get_reject_proportion() * self.memory_size_for_write:
            self.logger.debug("The total storage group mem costs are too large, call for flushing. Current sg cost is {}.".format(self.total_storage_group_mem_cost))
            choose_mem_tables_to_mark_flush(ts_file_processor)
            return True
        else:
            self.logger.info("Change system to reject status. Triggered by: logical SG ({}, mem cost delta {}, totalSgMemCost {}).".format(storage_group_info.get_logical_storage_group_name(), delta, self.total_storage_group_mem_cost))
            self.rejected = True
            if choose_mem_tables_to_mark_flush(ts_file_processor):
                if self.total_storage_group_mem_cost < self.memory_size_for_write:
                    return True
                else:
                    raise WriteProcessRejectException("Total Storage Group MemCost {} is over than memorySizeForWriting {}".format(self.total_storage_group_mem_cost, self.memory_size_for_write))
            else:
                return False

    def reset_storage_group_status(self, storage_group_info: StorageGroupInfo):
        delta = 0
        if self.reported_storage_group_mem_cost_map[storage_group_info] > 0:
            delta = self.reported_storage_group_mem_cost_map[storage_group_info] - storage_group_info.mem_cost
            self.total_storage_group_mem_cost -= delta
            storage_group_info.set_last_reported_size(storage_group_info.mem_cost)
            self.reported_storage_group_mem_cost_map[storage_group_info] = storage_group_info.mem_cost
        if self.total_storage_group_mem_cost >= self.config.get_flush_proportion() * self.memory_size_for_write and self.total_storage_group_mem_cost < self.config.get_reject_proportion() * self.memory_size_for_write:
            self.logger.debug("SG ({}) released memory (delta: {}), but still exceeding flush proportion (totalSgMemCost {}).".format(storage_group_info.get_logical_storage_group_name(), delta, self.total_storage_group_mem_cost))
            if self.rejected:
                self.logger.info("SG ({}) released memory (delta: {}), set system to normal status (totalSgMemCost {}).".format(storage_group_info.get_logical_storage_group_name(), delta, self.total_storage_group_mem_cost))
        elif self.total_storage_group_mem_cost >= self.config.get_reject_proportion() * self.memory_size_for_write:
            self.logger.warn("SG ({}) released memory (delta: {}), but system is still in reject status (totalSgMemCost {}).".format(storage_group_info.get_logical_storage_group_name(), delta, self.total_storage_group_mem_cost))
        else:
            self.logger.debug("SG ({}) released memory (delta: {}), system is in normal status (totalSgMemCost {}).".format(storage_group_info.get_logical_storage_group_name(), delta, self.total_storage_group_mem_cost))

    def add_flushing_mem_table_cost(self, flushing_mem_table_cost: long):
        self.flushing_mem_tables_cost += flushing_mem_table_cost

    def reset_flushing_mem_table_cost(self, flushing_mem_table_cost: long):
        self.flushing_mem_tables_cost -= flushing_mem_table_cost

    def log_current_total_sg_memory(self):
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug("Current Sg cost is {}".format(self.total_storage_group_mem_cost))

    def choose_mem_tables_to_mark_flush(self, current_ts_file_processor: TsFileProcessor) -> bool:
        # If invoke flush by replaying logs, do not flush now!
        if len(self.reported_storage_group_mem_cost_map) == 0:
            return False
        all_ts_file_processors = PriorityQueue()
        for storage_group_info in self.reported_storage_group_mem_cost_map.keys():
            all_ts_file_processors.addAll(storage_group_info.getAllReportedTsp())
        is_current_ts_file_processor_selected = False
        mem_cost = 0
        active_mem_size = self.total_storage_group_mem_cost - self.flushing_mem_tables_cost
        while active_mem_size - mem_cost > self.config.get_flush_proportion() * self.memory_size_for_write:
            if all_ts_file_processors.isEmpty():
                return False
            selected_ts_file_processor = all_ts_file_processors.peek()
            mem_cost += selected_ts_file_processor.work_mem_table_ram_cost
            selected_ts_file_processor.set_work_mem_table_should_flush()
            flush_task_submit_thread_pool.submit(lambda: selected_ts_file_processor.submit_a_flush_task())
            if selected_ts_file_processor == current_ts_file_processor:
                is_current_ts_file_processor_selected = True
            all_ts_file_processors.poll()
        return is_current_ts_file_processor_selected

    def get_total_mem_table_size(self) -> long:
        return self.total_storage_group_mem_cost

    def get_flush_threshold(self) -> double:
        return self.config.get_flush_proportion() * self.memory_size_for_write

    def get_reject_threshold(self) -> double:
        return self.config.get_reject_proportion() * self.memory_size_for_write

    def flushing_mem_table_num(self) -> int:
        return FlushManager.getInstance().get_number_of_working_tasks()

class InstanceHolder:
    instance = SystemInfo()
