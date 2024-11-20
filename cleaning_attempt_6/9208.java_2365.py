class DBParms:
    MASTER_TABLE_ROOT_BUFFER_ID_PARM = 0
    DATABASE_ID_HIGH_PARM = 1
    DATABASE_ID_LOW_PARM = 2

    NODE_TYPE_SIZE = 1
    DATA_LENGTH_SIZE = 4
    VERSION_SIZE = 1
    NODE_TYPE_OFFSET = 0
    DATA_LENGTH_OFFSET = NODE_TYPE_SIZE
    VERSION_OFFSET = DATA_LENGTH_OFFSET + DATA_LENGTH_SIZE
    PARM_BASE_OFFSET = VERSION_OFFSET + VERSION_SIZE

    VERSION = 1

    def __init__(self, buffer_mgr, create=False):
        self.buffer_mgr = buffer_mgr
        if create:
            try:
                buffer = buffer_mgr.create_buffer()
                if buffer.id != 0:
                    raise AssertionError("DBParms must be first buffer allocation")
                buffer.clear()
                buffer[NODE_TYPE_OFFSET] = NodeMgr.CHAINED_BUFFER_DATA_NODE  # we mimic a single buffer chained-buffer
                buffer[DATA_LENGTH_OFFSET] = VERSION_SIZE
                buffer[VERSION_OFFSET] = self.VERSION
            finally:
                if buffer is not None:
                    buffer_mgr.release_buffer(buffer)
        self.refresh()

    @staticmethod
    def get_offset(parm):
        return PARM_BASE_OFFSET + (parm * 4)

    @staticmethod
    def poke(file, parm, value):
        try:
            buffer = LocalBufferFile.peek(file, 0)
            if buffer[NODE_TYPE_OFFSET] != NodeMgr.CHAINED_BUFFER_DATA_NODE:
                raise AssertionError("Unexpected DBParms buffer node type")
            if buffer[VERSION_OFFSET] != self.VERSION:
                raise AssertionError("Unsupported DBParms format")

            store_parm(parm, value, buffer)

            LocalBufferFile.poke(file, 0, buffer)
        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def store_parm(parm, value, buffer):
        max_parm_cnt = (buffer.length - PARM_BASE_OFFSET) // 4
        if parm < 0 or parm >= max_parm_cnt:
            raise ArrayIndexOutOfBoundsException("Invalid parameter index:" + str(parm))
        size = (buffer[DATA_LENGTH_OFFSET] - self.VERSION_SIZE) // 4
        if parm >= size:
            # expand parameter space
            data_len = (parm + 1) * 4
            buffer[DATA_LENGTH_OFFSET] = data_len + self.VERSION_SIZE

        buffer[DBParms.get_offset(parm)] = value


    def set(self, parm, value):
        try:
            buffer = self.buffer_mgr.get_buffer(0)
            store_parm(parm, value, buffer)

            if parm >= self.size:
                # initialize unused parameters parameter space
                for i in range(self.size, parm + 1):
                    self.cache[i] = 0

                self.size = parm + 1

            self.cache[parm] = value
        finally:
            self.buffer_mgr.release_buffer(buffer)


    def get(self, parm):
        try:
            return self.cache.get(parm)
        except NoValueException as e:
            raise ArrayIndexOutOfBoundsException()


    def refresh(self):
        try:
            buffer = self.buffer_mgr.get_buffer(0)

            if buffer[NODE_TYPE_OFFSET] != NodeMgr.CHAINED_BUFFER_DATA_NODE:
                raise AssertionError("Unexpected DBParms buffer node type")
            if buffer[VERSION_OFFSET] != self.VERSION:
                raise AssertionError("Unsupported DBParms format")

            self.size = (buffer[DATA_LENGTH_OFFSET] - self.VERSION_SIZE) // 4
            self.cache.clear()
            for i in range(self.size):
                self.cache[i] = buffer[DBParms.get_offset(i)]

        finally:
            self.buffer_mgr.release_buffer(buffer)
