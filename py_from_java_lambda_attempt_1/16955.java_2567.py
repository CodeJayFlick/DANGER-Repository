Here's your Java code translated into Python:

```Python
class AbstractCrossSpaceCompactionTask:
    def __init__(self,
                 full_storage_group_name: str,
                 time_partition: int,
                 current_task_num: int,
                 selected_sequence_files=None,
                 selected_unsequence_files=None):
        self.selected_sequence_files = selected_sequence_files or []
        self.selected_unsequence_files = selected_unsequence_files or []

    @property
    def selected_sequence_files(self):
        return self._selected_sequence_files

    @selected_sequence_files.setter
    def selected_sequence_files(self, value):
        if not isinstance(value, list) or not all(isinstance(file, dict) for file in value):
            raise ValueError("Selected sequence files must be a list of dictionaries")
        self._selected_sequence_files = value

    @property
    def selected_unsequence_files(self):
        return self._selected_unsequence_files

    @selected_unsequence_files.setter
    def selected_unsequence_files(self, value):
        if not isinstance(value, list) or not all(isinstance(file, dict) for file in value):
            raise ValueError("Selected unsequence files must be a list of dictionaries")
        self._selected_unsequence_files = value

    def check_valid_and_set_merging(self):
        for resource in self.selected_sequence_files:
            if (resource.get('isMerging', False) or
                    not resource.get('isClosed', True) or
                    not resource['tsFile'].exists()):
                return False

        for resource in self.selected_unsequence_files:
            if (resource.get('isMering', False) or
                    not resource.get('isClosed', True) or
                    not resource['tsFile'].exists()):
                return False

        for resource in self.selected_sequence_files:
            resource['setMerging'] = True

        for resource in self.selected_unsequence_files:
            resource['setMering'] = True

        return True

    def __str__(self):
        return f"{self.full_storage_group_name}-{self.time_partition} task seq file num is {len(self.selected_sequence_files)} , unseq file num is {len(self.selected_unsequence_files)}"
```

Note that Python does not have direct equivalent of Java's `@Override` annotation.