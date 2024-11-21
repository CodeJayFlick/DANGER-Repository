class PcodeXMLException(Exception):
    def __init__(self, msg, *args, **kwargs):
        if 'cause' in kwargs:
            super().__init__("XML comms: " + str(msg), *args, cause=kwargs['cause'])
        else:
            super().__init__("XML comms: " + str(msg))

# Example usage
try:
    # Some code that might raise an exception
except Exception as e:
    pcode_exception = PcodeXMLException("Error occurred", cause=e)
