class ThreadUtils:
    FUDGE_FACTOR = 4

    def recurse_on(thread_group: object, depth: int) -> bool:
        active_count = thread_group.activeCount()
        threads = [None] * (active_count * FUDGE_FACTOR)
        actual_number_of_threads = len(list(thread_group.enumerate(threads, False)))

        for ii in range(actual_number_of_threads):
            if threads[ii].getName().startswith("AWT-"):
                return True

        active_group_count = thread_group.activeGroupCount()
        thread_groups = [None] * (active_group_count * FUDGE_FACTOR)
        actual_number_of_thread_groups = len(list(thread_group.enumerate(thread_groups, False)))

        for ii in range(actual_number_of_thread_groups):
            recursed_value = recurse_on(thread_groups[ii], depth + 1)
            if recursed_value:
                return True

        return False

    @staticmethod
    def is_awt_thread_present() -> bool:
        current_thread = Thread.current_thread()
        thread_group = current_thread.getThreadGroup()

        while thread_group.getParent():
            thread_group = thread_group.getParent()

        return recurse_on(thread_group, 0)
