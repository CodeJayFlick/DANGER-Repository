class TextEditorService:
    def __init__(self):
        pass

    def edit(self, name: str, input_stream: bytes) -> None:
        """
        Shows an text editor component with the contents of the specified input stream.

        :param name: String name of file
        :param input_stream: Bytes-like object (e.g. a byte string or buffer)
        """
        # Note that in Python, we don't need to close the input stream explicitly,
        # as it will be garbage collected when no longer referenced.
