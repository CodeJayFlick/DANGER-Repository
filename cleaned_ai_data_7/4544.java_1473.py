class FunctionComparisonModel:
    def __init__(self):
        self.comparisons = []
        self.listeners = []

    def add_function_comparison_model_listener(self, listener):
        self.listeners.append(listener)

    def get_comparisons(self):
        return sorted(self.comparisons)

    def set_comparisons(self, comparisons):
        self.comparisons = comparisons

    def add_comparison(self, comparison):
        self.comparisons.append(comparison)

    def get_targets(self, source):
        targets = set()
        for fc in self.comparisons:
            if fc.get_source() == source:
                targets.update(fc.get_targets())
        return targets

    def compare_functions(self, functions):
        if not functions:
            return
        self.add_to_existing_comparisons(functions)
        self.create_new_comparisons(functions)
        self.fire_model_changed()

    def compare_functions(self, source, target):
        fc = self.get_or_create_comparison(source)
        fc.add_target(target)
        self.fire_model_changed()

    def remove_function(self, function):
        comparisons_to_remove = []
        for iter in enumerate(self.comparisons):
            if iter[1].get_source() == function:
                comparisons_to_remove.append(iter[0])
            elif any(t == function for t in iter[1].get_targets()):
                iter[1].get_targets().remove(function)
        [self.comparisons.pop(i) for i in reversed(comparisons_to_remove)]
        self.fire_model_changed()

    def remove_functions(self, program):
        sources = set()
        targets = set()
        for fc in self.comparisons:
            if fc.get_source().program == program:
                sources.add(fc.get_source())
            elif any(t.program == program for t in fc.get_targets()):
                targets.update([t for t in fc.get_targets() if t.program == program])
        [self.remove_function(f) for f in sources]
        [self.remove_function(f) for f in targets]

    def get_source_functions(self):
        return set(fc.get_source() for fc in self.comparisons)

    def get_target_functions(self, source=None):
        if not source:
            return set().union(*[fc.get_targets() for fc in self.comparisons])
        else:
            return {t for iter in enumerate(self.comparisons) if iter[1].get_source() == source and any(t == t for t in iter[1].get_targets())}

    def create_new_comparisons(self, functions):
        TaskLauncher.launch_modal("Creating Comparisons", lambda monitor: 
            [functions.remove(f) for f in self.get_source_functions()]
            .monitor.set_indeterminate(False)
            .message = "Creating new comparisons"
            .initialize(len(functions))
            for f in functions:
                if monitor.is_cancelled():
                    Msg.info(self, "Function comparison operation cancelled")
                    return
                fc = FunctionComparison()
                fc.source = f
                fc.add_targets(functions)
                self.comparisons.append(fc)
                monitor.increment_progress(1)

    def get_or_create_comparison(self, source):
        for fc in self.comparisons:
            if fc.get_source() == source:
                return fc
        fc = FunctionComparison()
        fc.source = source
        self.comparisons.append(fc)
        return fc

    def add_to_existing_comparisons(self, functions):
        for f in functions:
            [fc.add_target(f) for fc in self.comparisons]

    def fire_model_changed(self):
        [l.model_changed(self.get_comparisons()) for l in self.listeners]
