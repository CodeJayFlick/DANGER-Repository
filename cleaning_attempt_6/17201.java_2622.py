class StatMonitorMBean:
    def get_global_total_points_num(self):
        return 0  # Replace with actual implementation

    def get_global_req_success_num(self):
        return 0  # Replace with actual implementation

    def get_global_req_fail_num(self):
        return 0  # Replace with actual implementation

    def get_storage_group_total_points_num(self, storage_group_name: str) -> int:
        return 0  # Replace with actual implementation

    def get_system_directory(self) -> str:
        return ""  # Replace with actual implementation

    def get_data_size_in_byte(self) -> int:
        return 0  # Replace with actual implementation

    def is_write_ahead_log_status(self) -> bool:
        return False  # Replace with actual implementation

    def is_enable_stat_monitor(self) -> bool:
        return False  # Replace with actual implementation
