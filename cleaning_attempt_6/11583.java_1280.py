class UnsupportedFloatFormatException(Exception):
    def __init__(self, message="Unsupported float format"):
        super().__init__(message)

def main():
    try:
        # example usage
        raise UnsupportedFloatFormatException(42)
    except UnsupportedFloatFormatException as e:
        print(e)

if __name__ == "__main__":
    main()
