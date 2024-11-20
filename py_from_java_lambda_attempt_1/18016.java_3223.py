Here is the translation of the Java code into Python:

```Python
import time
from threading import Thread
import sqlite3
import mmap

class IoTDBLogFileSizeTest:
    def __init__(self):
        self.skip = True
        self.group_size = None
        self.runtime = 600000

    def setUp(self):
        if self.skip:
            return
        self.group_size = TSFileDescriptor().get_config().get_group_size_in_byte()
        TSFileDescriptor().get_config().set_group_size_in_byte(8 * 1024 * 1024)
        IoTDBDescriptor().get_config().set_memtable_size_threshold(8 * 1024 * 1024)

    def tearDown(self):
        if self.skip:
            return
        TSFileDescriptor().get_config().set_group_size_in_byte(self.group_size)
        IoTDBDescriptor().get_config().set_memtable_size_threshold(self.group_size)

    def test_seq_file(self):
        if self.skip:
            return

        buffers = [mmap.mmap(-1, 5242880), mmap.mmap(-1, 5242880)]
        write_thread = Thread(target=self.write_to_db, args=(buffers,))
        write_thread.start()
        time.sleep(self.runtime)
        write_thread.interrupt()

    def test_unsequence(self):
        if self.skip:
            return

        buffers = [mmap.map(None, 5242880), mmap.map(None, 5242880)]
        write_thread = Thread(target=self.write_to_db, args=(buffers,))
        write_thread.start()
        time.sleep(self.runtime)
        write_thread.interrupt()

    def execute_sql(self, sqls):
        try:
            conn = sqlite3.connect('iotdb.db')
            c = conn.cursor()
            for sql in sqls:
                c.execute(sql)
            conn.commit()
        except Exception as e:
            print(str(e))

    def write_to_db(self, buffers):
        cnt = 0
        while not Thread.interrupted():
            try:
                conn = sqlite3.connect('iotdb.db')
                c = conn.cursor()
                sql = f"INSERT INTO root.logFileTest.seq(timestamp,val) VALUES ({cnt}, {cnt})"
                c.execute(sql)
                log_node = MultiFileLogNodeManager().get_node("root.logFileTest.seq", lambda: buffers)
                wal_file = open(log_node.get_log_directory() + File.separator + ExclusiveWriteLogNode.WAL_FILE_NAME, 'r')
                if wal_file.tell() > maxLength[0]:
                    maxLength[0] = wal_file.tell()
            except Exception as e:
                print(str(e))
        conn.close()

    def __del__(self):
        for buffer in buffers:
            mmap.Unmap(-1, len(buffer))

if __name__ == "__main__":
    test = IoTDBLogFileSizeTest()
    test.setUp()
    test.test_seq_file()
    test.tearDown()
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your environment.