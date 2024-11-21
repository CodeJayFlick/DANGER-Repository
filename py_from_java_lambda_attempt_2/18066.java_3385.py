Here is the translation of the Java code into Python:

```Python
import logging
from threading import Timer
from time import sleep

class SessionPoolTest:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_insert(self):
        pool = SessionPool("127.0.0.1", 6667, "root", "root", 3)
        service = ThreadPoolExecutor(max_workers=10)

        for i in range(10):
            no = i
            service.submit(lambda: self.insert_record(pool, no))

        service.shutdown()
        try:
            pool.close()
            time.sleep(1)  # wait until the session is closed
            assert pool.current_available_size() <= 3 and pool.current_occupied_size() == 0
        except Exception as e:
            logging.error("insert failed", e)
            self.fail(e)

    def test_incorrect_sql(self):
        pool = SessionPool("127.0.0.1", 6667, "root", "root", 3)
        try:
            pool.insert_record(".root.sg1.d1", 1, ["s"], [TSDataType.INT64], [(long) 3])
            assert pool.current_available_size() == 1
        except Exception as e:
            pass

    def test_incorrect_execute_query_statement(self):
        pool = SessionPool("127.0.0.1", 6667, "root", "root", 3)
        service = ThreadPoolExecutor(max_workers=10)

        for i in range(10):
            no = i
            service.submit(lambda: self.execute_query_statement(pool, no))

        service.shutdown()
        try:
            time.sleep(10)  # wait until the session is closed
            assert pool.current_available_size() <= 3 and pool.current_occupied_size() == 0
        except Exception as e:
            logging.error("incorrectExecuteQueryStatement failed", e)
            self.fail(e)

    def test_execute_query_statement(self):
        pool = SessionPool("127.0.0.1", 6667, "root", "root", 3)
        service = ThreadPoolExecutor(max_workers=10)

        for i in range(10):
            no = i
            service.submit(lambda: self.execute_query_statement(pool, no))

        service.shutdown()
        try:
            time.sleep(10)  # wait until the session is closed
            assert pool.current_available_size() <= 3 and pool.current_occupied_size() == 0
        except Exception as e:
            logging.error("executeQueryStatement failed", e)
            self.fail(e)

    def test_execute_raw_data_query(self):
        pool = SessionPool("127.0.0.1", 6667, "root", "root", 3)
        service = ThreadPoolExecutor(max_workers=10)

        for i in range(10):
            no = i
            service.submit(lambda: self.execute_raw_data_query(pool, no))

        service.shutdown()
        try:
            time.sleep(10)  # wait until the session is closed
            assert pool.current_available_size() <= 3 and pool.current_occupied_size() == 0
        except Exception as e:
            logging.error("executeRawDataQuery failed", e)
            self.fail(e)

    def test_try_if_the_server_is_restart(self):
        pool = SessionPool("127.0.0.1", 6667, "root", "root", 3, 1, 60000, False, None, False, Config.DEFAULT_CONNECTION_TIMEOUT_MS)
        write10Data(pool, True)

        try:
            wrapper = self.execute_query_statement(pool, 2)
            EnvironmentUtils.stopDaemon()
            while wrapper.hasNext():
                wrapper.next()

            pool.closeResultSet(wrapper)
            pool.close()
            EnvironmentUtils.reactiveDaemon()
            new_pool = SessionPool("127.0.0.1", 6667, "root", "root", 3, 1, 60000, False, None, False, Config.DEFAULT_CONNECTION_TIMEOUT_MS)
            self.correct_query(new_pool, DEFAULT_QUERY_TIMEOUT)
            pool.close()

        except Exception as e:
            logging.error("tryIfTheServerIsRestart failed", e)
            self.fail(e)

    def test_try_if_the_server_is_restart_but_data_is_gotten(self):
        pool = SessionPool("127.0.0.1", 6667, "root", "root", 3, 1, 60000, False, None, False, Config.DEFAULT_CONNECTION_TIMEOUT_MS)
        write10Data(pool, True)

        try:
            wrapper = self.execute_query_statement(pool, 2)
            assertEquals(0, pool.current_available_size())
            assertEquals(1, pool.current_occupied_size())

            while wrapper.hasNext():
                wrapper.next()

            pool.closeResultSet(wrapper)
            assertEquals(1, pool.current_available_size())
            assertEquals(0, pool.current_occupied_size())

        except Exception as e:
            logging.error("tryIfTheServerIsRestartButDataIsGotten failed", e)
            self.fail(e)

    def test_restart(self):
        pool = SessionPool("127.0.0.1", 6667, "root", "root", 3, 1, 60000, False, None, False, Config.DEFAULT_CONNECTION_TIMEOUT_MS)
        write10Data(pool, True)

        try:
            self.insert_record(pool, 2)
        except Exception as e:
            logging.error("insert failed", e)
            self.fail(e)

    def test_close(self):
        pool = SessionPool("127.0.0.1", 6667, "root", "root", 3, 1, 60000, False, None, False, Config.DEFAULT_CONNECTION_TIMEOUT_MS)
        try:
            pool.close()
            time.sleep(1)  # wait until the session is closed
            self.insert_record(pool, 2)

        except Exception as e:
            logging.error("close failed", e)
            self.fail(e)

    def test_builder(self):
        builder = SessionPool.Builder().host("localhost").port(1234).max_size(10).user("abc").password("123").fetch_size(1).wait_to_get_session_timeout_in_ms(2).enable_cache_leader(True).enable_compression(True).zone_id(ZoneOffset.UTC).connection_timeout_in_ms(3)
        pool = builder.build()

        self.assertEqual(pool.host, "localhost")
        self.assertEqual(pool.port, 1234)
        self.assertEqual(pool.user, "abc")
        self.assertEqual(pool.password, "123")
        self.assertEqual(pool.max_size, 10)
        self.assertEqual(pool.fetch_size, 1)
        self.assertEqual(pool.wait_to_get_session_timeout_in_ms, 2)
        self.assertTrue(pool.enable_cache_leader)
        self.assertTrue(pool.enable_compression)
        self.assertEqual(pool.connection_timeout_in_ms, 3)

    def insert_record(self, pool, no):
        try:
            pool.insert_record("root.sg1.d1", no, ["s" + str(no)], [TSDataType.INT64], [(long) no])
        except Exception as e:
            logging.error("insert failed", e)
            self.fail(e)

    def execute_query_statement(self, pool, no):
        try:
            wrapper = pool.execute_query_statement("select * from root.sg1.d1 where time > " + str(no))
            while wrapper.hasNext():
                wrapper.next()
        except Exception as e:
            logging.error("executeQueryStatement failed", e)
            self.fail(e)

    def execute_raw_data_query(self, pool, no):
        try:
            wrapper = pool.execute_raw_data_query(["root.sg1.d1.s" + str(no)], no, no + 1)
            while wrapper.hasNext():
                session_dataset = wrapper.next()
                self.assertEqual(session_dataset.get_timestamp(), long(no))
        except Exception as e:
            logging.error("executeRawDataQuery failed", e)
            self.fail(e)

    def correct_query(self, pool, timeout_in_ms):
        service = ThreadPoolExecutor(max_workers=10)

        for i in range(10):
            no = i
            service.submit(lambda: self.execute_query_statement(pool, no))

        service.shutdown()
        try:
            time.sleep(timeout_in_ms)  # wait until the session is closed
            assert pool.current_available_size() <= 3 and pool.current_occupied_size() == 0
        except Exception as e:
            logging.error("correctQuery failed", e)
            self.fail(e)

    def write10Data(self, pool, fail_when_throw_exception):
        for i in range(10):
            try:
                pool.insert_record("root.sg1.d1", i, ["s" + str(i)], [TSDataType.INT64], [(long) i])
            except Exception as e:
                if fail_when_throw_exception:
                    self.fail(e)
```

Please note that this is a direct translation of the Java code into Python and may not be perfect. The `assert` statements are used to check for certain conditions, but they will raise an `AssertionError` if the condition is false.