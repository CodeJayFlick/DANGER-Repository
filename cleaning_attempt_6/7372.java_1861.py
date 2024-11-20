class BoardID:
    iPhone2G = 0x0
    iPhone3G = 0x04
    iPhone3GS = 0x00
    iPodTouch1stGen = 0x02
    iPodTouch2ndGen = 0x00
    iPodTouch3rdGen = 0x02

    def __init__(self, board_id):
        self.board_id = board_id

    @property
    def get_board_id(self):
        return self.board_id


# Example usage:
board1 = BoardID(BoardID.iPhone2G)
print(board1.get_board_id)  # Output: 0x0

board2 = BoardID(BoardID.iPodTouch3rdGen)
print(board2.get_board_id)  # Output: 0x02
