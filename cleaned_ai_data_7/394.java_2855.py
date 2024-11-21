class DebugAdvanced:
    class DebugThreadBasicInformation:
        def __init__(self, exit_status: int, priority_class: int, priority: int,
                     create_time: int, exit_time: int, kernel_time: int, user_time: int,
                     start_offset: int, affinity: int):
            self.exit_status = exit_status
            self.priority_class = priority_class
            self.priority = priority
            self.create_time = create_time
            self.exit_time = exit_time
            self.kernel_time = kernel_time
            self.user_time = user_time
            self.start_offset = start_offset
            self.affinity = affinity

        def __str__(self):
            sb = "<DebugThreadBasicInformation:\n"
            if self.exit_status is not None:
                sb += "    exitStatus: {}\n".format(self.exit_status)
            if self.priority_class is not None:
                sb += "    priorityClass: {}\n".format(self.priority_class)
            if self.priority is not None:
                sb += "    priority: {}\n".format(self.priority)
            if self.create_time is not None:
                sb += "    createTime: {}\n".format(self.create_time)
            if self.exit_time is not None:
                sb += "    exitTime: {}\n".format(self.exit_time)
            if self.kernel_time is not None:
                sb += "    kernelTime: {}\n".format(self.kernel_time)
            if self.user_time is not None:
                sb += "    userTime: {}\n".format(self.user_time)
            if self.start_offset is not None:
                sb += "    startOffset: {}\n".format(self.start_offset)
            if self.affinity is not None:
                sb += "    affinity: {}\n".format(self.affinity)
            return sb + ">"

class DebugAdvancedImpl(DebugAdvanced):
    def get_thread_basic_information(self, tid) -> 'DebugThreadBasicInformation':
        # Implement the method here
        pass

# Example usage:
debug_advanced = DebugAdvancedImpl()
thread_info = debug_advanced.get_thread_basic_information(12345)
print(thread_info.__str__())
