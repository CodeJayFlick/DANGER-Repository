class MarkupItemValueTextFilter:
    def __init__(self, controller, table):
        pass  # No direct equivalent in Python for constructor-like method.

    def create_empty_copy(self):
        return self.__class__(self.controller, self.table)

    def passes_filter(self, adapter):
        return self.passes_value_text_filter_impl(adapter)

    def passes_value_text_filter_impl(self, adapter):
        filter_text = self.get_text_field_text()
        if not filter_text or len(filter_text.strip()) == 0:
            return True

        source_value = adapter.source_value
        destination_value = adapter.destination_value

        if (source_value and 
           str(source_value).lower().find(filter_text.lower()) != -1):
            return True

        if (destination_value and 
           str(destination_value).lower().find(filter_text.lower()) != -1):
            return True

        return False


class VTMarkupItem:
    def __init__(self, source_value=None, destination_value=None):
        self.source_value = source_value
        self.destination_value = destination_value

    @property
    def get_original_destination_value(self):
        return self.destination_value

    @property
    def get_source_value(self):
        return self.source_value


class GTable:
    pass  # No direct equivalent in Python for this class.

class VTController:
    pass  # No direct equivalent in Python for this class.
