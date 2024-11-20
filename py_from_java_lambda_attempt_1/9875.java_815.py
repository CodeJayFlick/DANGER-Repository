Here is the translation of the Java code into Python:

```Python
class ThreadedTableModelUpdateMgr:
    def __init__(self, model: 'ThreadedTableModel', monitor):
        self.model = model
        self.monitor = validate_monitor(monitor)
        self.max_add_remove_count = 3000

        # see notes on DummyCancellableTaskMonitor...(in an ideal world this will be handled by wrapping the given monitor with one that is usable by the Jobs of this class).
        SystemUtilities.assertTrue(self.monitor.is_cancel_enabled(), "In order for this update manager to work correctly ...")

        self.add_remove_updater = SwingUpdateManager(5000, 10000 * 20, lambda: process_add_remove_items())

        # weakly consistent iterator so that clients can remove listeners on notification
        self.listeners = ConcurrentListenerSet()

    def get_synchronizing_lock(self):
        return self.add_remove_updater

    @property
    def max_add_remove_count(self):
        n = self.model.get_row_count()
        cuttoff = int(n * 0.1)
        return max(self.max_add_remove_count, cuttoff)

    def cancel_all_jobs(self):
        with self.add_remove_updater:
            if current_job is not None:
                current_job.cancel()

            pending_job = None
            add_remove_wait_list.clear()

    def reload(self):
        with self.add_remove_updater:
            cancel_all_jobs()
            run_job(LoadJob(self.model, self.monitor))

    def reload_specific_data(self, data: List['T']):
        with self.add_remove_updater:
            cancel_all_jobs()
            table_data = TableData.create_full_dataset(data)
            run_job(LoadSpecificDataJob(self.model, self.monitor, table_data))

    @property
    def is_busy(self):
        return thread is not None or pending_job is not None or add_remove_updater.is_busy() or not add_remove_wait_list.empty()

    def set_update_delay(self, update_delay_millis: int, max_update_delay_millis: int):
        self.add_remove_updater.dispose()
        self.add_remove_updater = SwingUpdateManager(update_delay_millis, max_update_delay_millis, lambda: process_add_remove_items())

    @property
    def task_monitor(self):
        return self.monitor

    def set_task_monitor(self, monitor):
        self.monitor = validate_monitor(monitor)

    def add_threaded_table_listener(self, listener: 'ThreadedTableModelListener'):
        self.listeners.add(listener)

    def remove_threaded_table_listener(self, listener: 'ThreadedTableModelListener'):
        self.listeners.remove(listener)

    @property
    def is_cancelled(self):
        return self.monitor.is_cancelled()

    def dispose(self):
        with self.add_remove_updater:
            listeners.clear()
            monitor.cancel()
            monitor = PermantentlyCancelledMonitor()
            cancel_all_jobs()
            add_remove_updater.dispose()

    def update_now(self):
        self.add_remove_updater.update_now()

    @property
    def is_pending(self):
        return not add_remove_wait_list.empty() or thread is not None

    def run_job(self, job: 'TableUpdateJob'):
        with self.add_remove_updater:
            if thread is not None:
                return  # if thread exists, it will handle any pending job
            thread = Thread(thread_runnable)
            thread.start()
            Swing.run_later(notify_pending)

    @property
    def current_job(self):
        return next_job

    def get_next_job(self):
        with self.add_remove_updater:
            current_job = pending_job
            pending_job = None
            if current_job is not None:
                job_done()

    def notify_pending(self):
        for listener in listeners:
            listener.load_pending()
        Swing.run_later(notify_cancelled)

    @property
    def thread(self):
        return self.thread

    def process_add_remove_items(self):
        with self.add_remove_updater:
            if add_remove_wait_list.empty():
                return  # no more work to do
            run_job(AddRemoveJob(self.model, add_remove_wait_list, self.monitor))
            add_remove_wait_list = []

    @property
    def is_sorting(self):
        return current_job is not None and isinstance(current_job, SortJob)

    def sort(self, sorting_context: 'TableSortingContext', force_sort: bool):
        with self.add_remove_updater:
            if current_job is not None and pending_job is None and current_job.request_sort(sorting_context, force_sort):
                return  # job already has the work
            run_job(SortJob(self.model, self.monitor, sorting_context, force_sort))

    def filter(self):
        with self.add_remove_updater:
            if current_job is not None and pending_job is None and current_job.request_filter():
                return  # job already has the work
            run_job(FilterJob(self.model, self.monitor))

    @property
    def notify_done(self):
        for listener in listeners:
            listener.loading_finished(False)
        Swing.run_later(notify_cancelled)

    @property
    def notify_cancelled(self):
        for listener in listeners:
            listener.loading_finished(True)
        Swing.run_later(notify_pending)

    class PermantentlyCancelledMonitor(TaskMonitorAdapter):
        def __init__(self):
            self.set_cancel_enabled(True)
            self.cancel()

        def clear_cancelled(self):
            pass

class ConcurrentListenerSet:
    def add(self, listener: 'ThreadedTableModelListener'):
        # implementation omitted for brevity
        pass

class SwingUpdateManager:
    def __init__(self, delay_millis: int, max_delay_millis: int, update_func):
        self.delay = delay_millis
        self.max_delay = max_delay_millis
        self.update_func = update_func

    @property
    def is_busy(self):
        return False  # implementation omitted for brevity

    def dispose(self):
        pass  # implementation omitted for brevity

    def update_now(self):
        process_add_remove_items()

class TableUpdateJob:
    def __init__(self, model: 'ThreadedTableModel', monitor):
        self.model = model
        self.monitor = monitor

    @property
    def is_cancelled(self):
        return False  # implementation omitted for brevity

    def run(self):
        pass  # implementation omitted for brevity

class LoadJob(TableUpdateJob):
    def __init__(self, model: 'ThreadedTableModel', monitor):
        super().__init__(model, monitor)

    @property
    def is_cancelled(self):
        return False  # implementation omitted for brevity

    def run(self):
        pass  # implementation omitted for brevity

class LoadSpecificDataJob(LoadJob):
    def __init__(self, model: 'ThreadedTableModel', monitor, table_data):
        super().__init__(model, monitor)
        self.table_data = table_data

    @property
    def is_cancelled(self):
        return False  # implementation omitted for brevity

    def run(self):
        pass  # implementation omitted for brevity

class SortJob(TableUpdateJob):
    def __init__(self, model: 'ThreadedTableModel', monitor, sorting_context, force_sort):
        super().__init__(model, monitor)
        self.sorting_context = sorting_context
        self.force_sort = force_sort

    @property
    def is_cancelled(self):
        return False  # implementation omitted for brevity

    def run(self):
        pass  # implementation omitted for brevity

class FilterJob(TableUpdateJob):
    def __init__(self, model: 'ThreadedTableModel', monitor):
        super().__init__(model, monitor)

    @property
    def is_cancelled(self):
        return False  # implementation omitted for brevity

    def run(self):
        pass  # implementation omitted for brevity