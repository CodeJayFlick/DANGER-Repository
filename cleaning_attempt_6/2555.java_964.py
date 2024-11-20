class TraceConflictedMappingException(Exception):
    def __init__(self, message, conflict):
        super().__init__(message)
        self.conflict = conflict

    @property
    def conflict(self):
        return self._conflict

# Example usage:
try:
    # some code that might raise an exception
except TraceConflictedMappingException as e:
    print(f"Conflict found: {e.conflict}")
