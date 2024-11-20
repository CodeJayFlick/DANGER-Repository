class DIEAMonitoredIterator:
    def __init__(self):
        pass

    @staticmethod
    def iterable(prog, monitor_message, task_monitor):
        return IterableDIEAggregate(prog, monitor_message, task_monitor)

    class SimpleDIEAMonitoredIterator(Iterator[DIEAggregate]):
        def __init__(self, prog, monitor_message, task_monitor):
            self.monitor = task_monitor
            self.monitor_message = monitor_message
            self.aggregate_total_count = len(prog.get_aggregates())
            self.aggregate_iterator = iter(prog.get_aggregates())

            self.monitor.set_indeterminate(False)
            self.monitor.set_show_progress_value(True)
            self.monitor.initialize(self.aggregate_total_count)
            self.monitor.set_message(monitor_message)

        def hasNext(self):
            return next(iter([]), False) if not self.aggregate_iterator else True

        def next(self):
            try:
                diea = next(self.aggregate_iterator)
                self.monitor.increment_progress(1)
                return diea
            except StopIteration:
                raise NoSuchElementException()

    class PagedDIEAMonitoredIterator(Iterator[DIEAggregate]):
        def __init__(self, prog, monitor_message, task_monitor):
            self.prog = prog
            self.monitor = task_monitor
            self.monitor_message = monitor_message
            self.cu_count = len(prog.get_compilation_units())
            self.aggregate_total_count = len(prog.get_aggregates())

            self.cu_iterator = iter(prog.get_compilation_units())
            self.aggregate_iterator = None

            self.monitor.set_indeterminate(False)
            self.monitor.set_show_progress_value(True)
            self.monitor.initialize(self.aggregate_total_count)
            self.monitor.set_message(monitor_message)

        def update_monitor_message(self):
            self.monitor.set_maximum(self.aggregate_total_count)
            self.monitor.set_message(f"{self.monitor_message} - Compilation Unit #{next(iter([]), 0)}/{self.cu_count}")

        def finalize_monitor_message(self):
            self.monitor.set_message(f"{self.monitor_message} - Done")

        def hasNext(self):
            while True:
                if not self.aggregate_iterator and next(iter([]), False):
                    cu = next(self.cu_iterator)
                    try:
                        self.prog.set_current_compilation_unit(cu, self.monitor)
                    except (IOError, DWARFException) as e:
                        Msg.warn("Error when reading DIE entries for CU #{}.".format(cu.get_comp_unit_number()), e)
                        return False
                    except CancelledException:
                        pass  # no need to emit warning

                    self.aggregate_iterator = iter(self.prog.get_aggregates())
                    self.update_monitor_message()
                elif not next(iter([]), True):
                    self.finalize_monitor_message()
                    return False
                else:
                    if not self.aggregate_iterator and not next(iter([]), False):
                        raise NoSuchElementException()

        def next(self):
            try:
                diea = next(self.aggregate_iterator)
                self.monitor.increment_progress(1)
                return diea
            except StopIteration:
                raise NoSuchElementException()


class IterableDIEAggregate:
    def __init__(self, prog, monitor_message, task_monitor):
        if prog.get_import_options().is_preload_all_dies():
            iterator = SimpleDIEAMonitoredIterator(prog, monitor_message, task_monitor)
        else:
            iterator = PagedDIEAMonitoredIterator(prog, monitor_message, task_monitor)

    def __iter__(self):
        return self


class DIEAggregate:
    pass
