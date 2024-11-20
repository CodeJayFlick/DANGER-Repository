class DebuggerRegisterAccessException(Exception):
    def __init__(self, message, cause=None):
        super().__init__(message)
        self.cause = cause


def main():
    try:
        # Your code here that might raise this exception
        pass
    except DebuggerRegisterAccessException as e:
        print(f"Debugger Register Access Exception: {e}")


if __name__ == "__main__":
    main()
