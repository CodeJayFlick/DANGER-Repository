class ByteViewerLocationMemento:
    BLOCK_NUM = "Block Num"
    BLOCK_OFFSET = "Block Offset"

    def __init__(self, program, location, block_num, block_offset, column, viewer_position):
        super().__init__(program, location)
        self.block_num = block_num
        self.block_offset = block_offset
        self.viewer_position = viewer_position
        self.column = column

    @classmethod
    def from_save_state(cls, save_state, programs):
        instance = cls(super().from_save_state(save_state, programs), None, 0, BigInteger("0"), 0, ViewerPosition(0, 0, 0))
        instance.block_num = save_state.get_int(BYTEVIEWERLOCATIONMEMENTO.BLOCK_NUM, 0)
        instance.block_offset = int(str(save_state.get_string(BYTEVIEWERLOCATIONMEMENTO.BLOCK_OFFSET, "0")))
        instance.column = save_state.get_int("COLUMN", 0)
        return instance

    def get_block_offset(self):
        return self.block_offset

    def get_viewer_position(self):
        return self.viewer_position

    def get_block_num(self):
        return self.block_num

    def get_column(self):
        return self.column

    def save_state(self, save_state):
        super().save_state(save_state)
        save_state.put_int("INDEX", self.viewer_position.get_index())
        save_state.put_int("Y_OFFSET", self.viewer_position.get_y_offset())
        save_state.put_int("X_OFFSET", self.viewer_position.get_x_offset())
        save_state.put_int(BYTEVIEWERLOCATIONMEMENTO.BLOCK_NUM, self.block_num)
        if isinstance(self.block_offset, int):
            save_state.put_string(BYTEVIEWERLOCATIONMEMENTO.BLOCK_OFFSET, str(self.block_offset))
