class UDF:
    def __init__(self):
        pass

    @staticmethod
    def validate(validator) -> None:
        """This method is mainly used to validate parameters."""
        raise Exception("UDF validation not implemented")

    @staticmethod
    def before_destroy() -> None:
        """Release resources used in the UDF."""
        return
