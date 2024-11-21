class OutgoingCallsRootNode:
    def __init__(self, program, function, source_address, filter_duplicates, filter_depth):
        super().__init__(program, function, source_address, "FUNCTION_ICON", filter_duplicates, filter_depth)

    def recreate(self):
        return OutgoingCallsRootNode(self.program, self.function, self.source_address, self.filter_duplicates, self.filter_depth)

    @property
    def icon(self):
        return "FUNCTION_ICON"

    @property
    def name(self):
        return f"Outgoing References - {self.name}"

    @property
    def is_leaf(self):
        return False

    @property
    def tooltip(self):
        return None


# Note: Python does not have direct equivalent of Java's AtomicInteger. You can use int or any other integer type instead.
