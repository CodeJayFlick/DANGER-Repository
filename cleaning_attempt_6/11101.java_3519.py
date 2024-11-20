class Chunk:
    def __init__(self):
        self.start = None
        self.end = None
        self.row_to_file_position_map = {}
        self.lines_in_chunk = 0

# Note: In Python, we don't need a separate class for Pair as it's not necessary.
# If you want to use a custom pair class, you can define one and use it here.

# To convert the Java Map< Integer, Pair > rowToFilePositionMap to Python:
row_to_file_position_map = {}
