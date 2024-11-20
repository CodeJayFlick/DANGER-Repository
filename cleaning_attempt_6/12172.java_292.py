class SegmentMismatchException(Exception):
    def __init__(self, message="The segments of the addresses do not match."):
        super().__init__(message)

def main():
    try:
        # example usage
        raise SegmentMismatchException()
    except SegmentMismatchException as e:
        print(e)
