Here is the translation of the Java code to Python:
```python
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
```
Note that I had to make some assumptions about the Python equivalent of Java classes and methods. Specifically:

* `package ghidra.server.remote` is not translated directly; instead, I assume it's a namespace or module name.
* `public class ThreadUtils { ... }` becomes simply `class ThreadUtils: { ... }`.
* Methods are translated to functions with the same signature (e.g., `recurseOn` -> `recurse_on`, etc.).
* Fields and variables are translated similarly, using Python's syntax for defining constants (`FUDGE_FACTOR = 4`) or instance variables.
* The `ThreadGroup` class is not directly translatable; I assume it's a custom class in the Java code that doesn't have an equivalent in Python.

Please let me know if you'd like any further modifications!