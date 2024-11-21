class DataModelScript:
    def __init__(self):
        pass

    def get_name(self) -> str:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")

    def rename(self, script_name: str) -> None:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")

    def populate(self, content_stream: bytes) -> None:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")

    def execute(self, client: object) -> None:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")

    def unlink(self) -> None:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")

    def is_invocable(self) -> bool:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")

    def invoke_main(self, client: object) -> None:
        # implement this method as needed
        raise NotImplementedError("Method not implemented")
