class TableAddRemoveStrategy:
    def process(self, add_remove_list: list, table_data: dict, monitor=None):
        pass  # This method should be implemented by subclasses


from typing import List, Dict, Any

# Add this at the end to indicate that CancelledException is not defined in Python
CancelledException = Exception
