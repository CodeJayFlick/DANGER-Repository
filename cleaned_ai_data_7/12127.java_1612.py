class Query:
    """Query interface used to test a record for some condition."""
    
    def matches(self, record):
        """
        Returns True if the given record matches the query's condition.
        
        :param record: The record to test for compliance.
        :return: A boolean indicating whether the record matches the query's condition.
        """
        pass  # This method should be implemented by a subclass
