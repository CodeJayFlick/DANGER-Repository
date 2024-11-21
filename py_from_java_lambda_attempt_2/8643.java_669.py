Here is the translation of the Java code into Python:

```Python
class DiffController:
    def __init__(self, p1: 'Program', p2: 'Program', p1_limit_set: 'AddressSetView',
                 diff_filter: 'ProgramDiffFilter', merge_filter: 'ProgramMergeFilter',
                 monitor: 'TaskMonitor') -> None:
        self.merge_engine = ProgramMergeManager(p1, p2, p1_limit_set, monitor)
        self.merge_engine.set_diff_filter(diff_filter)
        self.merge_engine.set_merge_filter(merge_filter)
        self.p1_limit_set = p1_limit_set
        if not p1_limit_set:
            self.p1_current_address = p1.min_address()
        else:
            self.p1_current_address = p1_limit_set.min_address()
        self.p1_last_diffs = AddressSet()

    def get_program_one(self) -> 'Program':
        return self.merge_engine.get_program_one()

    def get_program_two(self) -> 'Program':
        return self.merge_engine.get_program_two()

    def get_limited_address_set(self) -> 'AddressSetView':
        return self.p1_limit_set

    def get_ignored_address_set(self) -> 'AddressSetView':
        return self.merge_engine.get_ignore_address_set()

    def get_restricted_address_set(self) -> 'AddressSetView':
        return self.merge_engine.get_restricted_address_set()

    def get_diff_filter(self) -> 'ProgramDiffFilter':
        return self.merge_engine.get_diff_filter()

    def set_diff_filter(self, filter: 'ProgramDiffFilter') -> None:
        self.merge_engine.set_diff_filter(filter)

    def get_merge_filter(self) -> 'ProgramMergeFilter':
        return self.merge_engine.get_merge_filter()

    def set_merge_filter(self, filter: 'ProgramMergeFilter') -> None:
        self.merge_engine.set_merge_filter(filter)

    def get_filtered_differences(self, monitor: 'TaskMonitor') -> 'AddressSetView':
        diffs1 = self.merge_engine.get_filtered_differences(monitor)
        program1 = self.get_program_one()
        program2 = self.get_program_two()
        monitor.set_message("Adjusting differences to code unit boundaries...")
        diff_set2 = DiffUtility.get_compatible_address_set(diffs1, program2)
        diff_cu_set2 = DiffUtility.get_code_unit_set(diff_set2, program2)
        monitor.set_message("Converting Diffs to program 1 set...")
        diffs1 = DiffUtility.get_compatible_address_set(diff_cu_set2, program1)
        if not self.p1_last_diffs == diffs1:
            self.p1_last_diffs = diffs1
        return diffs1

    def restrict_results(self, p1_address_set: 'AddressSetView', monitor: 'TaskMonitor') -> None:
        self.merge_engine.restrict_results(p1_address_set)
        differences_changed(monitor)

    def remove_result_restrictions(self, monitor: 'TaskMonitor') -> None:
        self.merge_engine.remove_result_restrictions()
        differences_changed(monitor)

    def apply(self, p1_address_set: 'AddressSetView', filter: 'ProgramMergeFilter',
              monitor: 'TaskMonitor') -> bool:
        return self.merge_engine.apply(p1_address_set, filter, monitor)

    def get_apply_message(self) -> str:
        return f"{self.merge_engine.get_error_message()} {self.merge_engine.get_info_message()}"

    def ignore(self, p1_address_set: 'AddressSetView', monitor: 'TaskMonitor') -> None:
        self.merge_engine.ignore(p1_address_set)
        differences_changed(monitor)

    def get_warnings(self) -> str:
        return self.merge_engine.get_warnings()

    def get_current_address(self) -> 'Address':
        return self.p1_current_address

    def go_to(self, address: 'Address') -> None:
        self.p1_current_address = address
        location_changed(address)

    def set_location(self, new_address: 'Address') -> None:
        if not self.p1_current_address == new_address:
            self.p1_current_address = new_address
            location_changed(new_address)

    def first(self) -> None:
        if not self.p1_last_diffs:
            return
        go_to(self.p1_last_diffs.min_address())

    @property
    def has_next(self) -> bool:
        return get_next_address() is not None

    def next(self) -> None:
        address = get_next_address()
        if address is not None:
            self.go_to(address)

    @property
    def has_previous(self) -> bool:
        return get_previous_address() is not None

    def previous(self) -> None:
        address = get_previous_address()
        if address is not None:
            self.go_to(address)

    def refresh(self, keep_ignored: bool, monitor: 'TaskMonitor') -> None:
        ignore_set = self.get_ignored_address_set()
        recompute_diffs(monitor)
        if keep_ignored:
            self.merge_engine.ignore(ignore_set)
        differences_changed(monitor)

    @staticmethod
    def location_changed(program1_location) -> None:
        for listener in DiffControllerListener.__dict__['listener_list']:
            listener.diff_location_changed(None, program1_location)

    @staticmethod
    def differences_changed() -> None:
        for listener in DiffControllerListener.__dict__['listener_list']:
            listener.differences_changed(None)
```

Note: The `AddressSetView`, `ProgramDiffFilter`, `ProgramMergeFilter`, and other classes are not defined here as they were part of the original Java code. You would need to define these classes or use equivalent Python classes for this translation to be complete.