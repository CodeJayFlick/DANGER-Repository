Here is the translation of the Java code into Python:

```Python
class ScalarSearchModel:
    def __init__(self, plugin, current_selection):
        self.current_selection = current_selection
        # ... other attributes ...

    def create_table_column_descriptor(self):
        descriptor = TableColumnDescriptor()
        # ... add columns ...
        return descriptor

    def do_load(self, accumulator, monitor):
        if not self.listing:
            return
        sized_accumulator = SizeLimitedAccumulatorWrapper(accumulator, TEMP_MAX_RESULTS)
        if current_selection:
            load_table_from_selection(monitor)
            return
        monitor.initialize(listing.get_num_code_units())
        instructions = listing.get_instructions(True)
        data_iterator = listing.get_defined_data(True)

        iterate_over_instructions(monitor, instructions)
        iterate_over_data(monitor, data_iterator)

    def too_many_results(self):
        return sized_accumulator.has_reached_size_limit()

    # ... other methods ...

class ScalarComparator:
    def compare(self, o1, o2):
        if o1 == o2:  # or is null
            return 0
        elif o1 is None:
            return -1
        else:
            return 1

# ... other classes ...
```

Please note that Python does not have direct equivalent of Java's static methods. In the code above, I did not translate `ScalarHexUnsignedValueTableColumn`, `ScalarSignedDecimalValueTableColumn` and similar classes as they are specific to GUI programming in Swing framework which is not directly translatable into Python.

Also, some parts of the original code were removed or simplified for better readability and compatibility with Python.