class TableChooserExecutor:
    def get_button_name(self):
        """A short name suitable for display in the "apply" button that indicates what the "apply" action does."""
        pass  # implement this method

    def execute(self, row_object: 'AddressableRowObject') -> bool:
        """
        Applies this executor's action to the given row object. Return True if the given object should be removed from the table.
        
        :param row_object: The AddressableRowObject to be executed upon
        :return: True if the rowObject should be removed from the table, False otherwise
        """
        pass  # implement this method


class AddressableRowObject:
    """An abstract class representing a row object that can be addressed."""
    pass
