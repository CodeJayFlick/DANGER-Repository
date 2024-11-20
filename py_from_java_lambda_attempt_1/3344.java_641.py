Here is the translation of the Java code into Python:

```Python
class MemoryMergeManager:
    def __init__(self):
        self.memory_phases = ["Memory"]
        self.result_programs = []
        self.my_programs = []
        self.original_programs = []
        self.latest_programs = []

    def get_name(self):
        return "Memory Block Merger"

    def get_description(self):
        return "Merge Memory Blocks"

    def apply(self, merge_panel=None):
        if merge_panel:
            conflict_option = merge_panel.get_selected_option()
            # If the "Use For All" check box is selected 
            # then save the option chosen for this conflict type.
            if merge_panel.get_use_for_all():
                self.memory_detail_choice = conflict_option

    def cancel(self, monitor=None):
        self.conflict_option = -2  # user canceled the merge operation
        return True

    def merge(self, task_monitor=None):
        try:
            num_blocks = len(self.my_programs[0].get_memory().get_blocks())
            if task_monitor is not None:
                task_monitor.initialize(num_blocks)
            for i in range(len(self.my_programs)):
                self.process_block_changes(i)

        except CancelledException as e:
            return False
        finally:
            pass

    def setup_conflicts(self):
        conflict_list = []
        result_blocks = []
        my_blocks = []
        latest_blocks = []
        orig_blocks = []

        for i in range(len(self.my_programs[0].get_memory().get_blocks())):
            if self.is_name_conflict(i) or self.is_permission_conflict(i) or self.is_comment_conflict(i):
                conflict_list.append(ConflictInfo(i, is_name_conflict(i), is_permission_conflict(i), is_comment_conflict(i)))

        return conflict_list

    def process_block_changes(self, index):
        if not self.is_name_conflict(index):
            my_name = self.my_programs[0].get_memory().get_blocks()[index].get_name()
            if my_name != orig_blocks[index].get_name():
                try:
                    result_blocks[index].set_name(get_unique_block_name(my_name))
                except LockException as e:
                    pass

        if not is_permission_conflict(index):
            permission = self.my_programs[0].get_memory().get_blocks()[index].is_read()
            if permission != orig_blocks[index].is_read():
                result_blocks[index].set_read(permission)

            permission = self.my_programs[0].get_memory().get_blocks()[index].is_write()
            if permission != orig_blocks[index].is_write():
                result_blocks[index].set_write(permission)

            permission = self.my_programs[0].get_memory().get_blocks()[index].is_execute()
            if permission != orig_blocks[index].is_execute():
                result_blocks[index].set_execute(permission)

            permission = self.my_programs[0].get_memory().get_blocks()[index].is_volatile()
            if permission != orig_blocks[index].is_volatile():
                result_blocks[index].set_volatile(permission)

        if not is_comment_conflict(index):
            my_comment = self.my_programs[0].get_memory().get_blocks()[index].get_comment()
            if my_comment and my_comment != orig_blocks[index].get_comment() or (my_comment == None):
                try:
                    result_blocks[index].set_comment(my_comment)
                except LockException as e:
                    pass

    def get_unique_block_name(self, name):
        unique_name = name
        cnt = 1
        while self.my_programs[0].get_memory().get_block(unique_name) is not None:
            unique_name += "_" + str(cnt)
            cnt += 1
        return unique_name


class ConflictInfo:
    def __init__(self, index, permission_conflict=False, name_conflict=False, comment_conflict=False):
        self.index = index
        self.permission_conflict = permission_conflict
        self.name_conflict = name_conflict
        self.comment_conflict = comment_conflict

# Helper functions for conflict detection and resolution.
def is_name_conflict(index):
    pass  # implement your logic here


def is_permission_conflict(index):
    pass  # implement your logic here


def is_comment_conflict(index):
    pass  # implement your logic here
```

Please note that the Java code has been translated into Python, but some parts of it may not be directly translatable. For example, `MemoryMergeManager` class in Java seems to have a lot of methods and variables which are specific to Java's Swing library or other libraries used in this context. In Python, you would need to implement these functionalities differently using Python's standard libraries (like Tkinter for GUI) if needed.

Also note that the conflict detection logic (`is_name_conflict`, `is_permission_conflict`, etc.) is not implemented here as it was part of the original Java code and might require additional context or implementation specific to your use case.