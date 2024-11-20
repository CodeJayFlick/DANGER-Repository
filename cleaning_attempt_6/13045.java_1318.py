class ErrorLogger:
    def trace(self, originator: object, message: object) -> None:
        pass  # implement logging logic here

    def trace(self, originator: object, message: object, throwable: Exception) -> None:
        pass  # implement logging logic here

    def debug(self, originator: object, message: object) -> None:
        pass  # implement logging logic here

    def debug(self, originator: object, message: object, throwable: Exception) -> None:
        pass  # implement logging logic here

    def info(self, originator: object, message: object) -> None:
        pass  # implement logging logic here

    def info(self, originator: object, message: object, throwable: Exception) -> None:
        pass  # implement logging logic here

    def warn(self, originator: object, message: object) -> None:
        pass  # implement logging logic here

    def warn(self, originator: object, message: object, throwable: Exception) -> None:
        pass  # implement logging logic here

    def error(self, originator: object, message: object) -> None:
        pass  # implement logging logic here

    def error(self, originator: object, message: object, throwable: Exception) -> None:
        pass  # implement logging logic here
