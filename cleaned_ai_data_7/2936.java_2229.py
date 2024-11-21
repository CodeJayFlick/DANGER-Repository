class SampleSearcher:
    def __init__(self, program):
        self.program = program

    def search(self, accumulator, monitor):
        it = self.program.get_function_manager().get_functions(True)
        monitor.initialize(len(it))
        while it.has_next():
            if monitor.is_cancelled():
                break
            fun = it.next()
            monitor.increment_progress(1)
            if fun.get_parameter_count() == 0:
                accumulator.add(SearchResults(fun.get_entry_point(), fun.get_name()))

    def get_program(self):
        return self.program

class SearchResults:
    def __init__(self, entry_point, name):
        self.entry_point = entry_point
        self.name = name
