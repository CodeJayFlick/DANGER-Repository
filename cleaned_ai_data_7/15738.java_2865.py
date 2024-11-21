class PostProcessor:
    def __init__(self):
        pass

    def process_output(self, ctx: object, list: 'NDList') -> object:
        """
        Processes the output NDList to the corresponding output object.

        Args:
            ctx (object): The toolkit used for post-processing.
            list ('NDList'): The output NDList after inference.

        Returns:
            object: The output object of expected type.

        Raises:
            Exception: If an error occurs during processing output.
        """
        pass
