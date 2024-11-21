class NoPrelinkSectionException(Exception):
    def __init__(self, message):
        super().__init__(message)

no_prelink_section_exception = NoPrelinkSectionException
