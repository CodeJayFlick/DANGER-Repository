import threading
from time import sleep
import random
import unittest
import mysql.connector

class IoTDBInsertWithQueryIT(unittest.TestCase):

    def setUp(self):
        self.close_stat_monitor()
        self.env_set_up()

    def tearDown(self):
        self.clean_env()

    @unittest.skip("Not implemented yet")
    def test_insert_with_query_test(self):
        # insert
        self.insert_data(0, 1000)

        # select
        self.select_and_count(1000)

        # insert
        self.insert_data(1000, 2000)

        # select
        self.select_and_count(2000)

    @unittest.skip("Not implemented yet")
    def test_insert_with_query_multi_thread_test(self):
        # insert
        self.insert_data(0, 1000)

        # select with multi thread
        threads = []
        for _ in range(5):
            t = threading.Thread(target=self.select_and_count, args=(1000,))
            threads.append(t)
            t.start()

        # insert
        self.insert_data(1000, 2000)

        # select with multi thread
        for t in threads:
            t.join()
            t.start()

    @unittest.skip("Not implemented yet")
    def test_insert_with_query_unsequence_test(self):
        # insert
        self.insert_data(0, 1000)

        # select
        self.select_and_count(1000)

        # insert
        self.insert_data(500, 1500)

        # select
        self.select_and_count(1500)

        # insert
        self.insert_data(2000, 3000)

        # select
        self.select_and_count(2500)

    @unittest.skip("Not implemented yet")
    def test_insert_with_query_multi_thread_unsequence_test(self):
        # insert
        self.insert_data(0, 1000)

        # select with multi thread
        threads = []
        for _ in range(5):
            t = threading.Thread(target=self.select_and_count, args=(1000,))
            threads.append(t)
            t.start()

        # insert
        self.insert_data(500, 1500)

        # select with multi thread
        for t in threads:
            t.join()
            t.start()

    @unittest.skip("Not implemented yet")
    def test_insert_with_query_flush_test(self):
        # insert
        self.insert_data(0, 1000)

        # select
        self.select_and_count(1000)

        # flush
        self.flush()

        # insert
        self.insert_data(1000, 2000)

        # select
        self.select_and_count(2000)

    @unittest.skip("Not implemented yet")
    def test_flush_with_query_test(self):
        # insert
        self.insert_data(0, 1000)

        # select with flush
        threads = []
        for _ in range(5):
            t = threading.Thread(target=self.select_and_count, args=(1000,))
            threads.append(t)
            t.start()

        # insert
        self.insert_data(500, 1500)

        # select with flush
        for t in threads:
            t.join()
            t.start()

    @unittest.skip("Not implemented yet")
    def test_flush_with_query_unorder_test(self):
        # insert
        self.insert_data(0, 100)
        self.insert_data(500, 600)

        # select
        self.select_and_count(200)

        self.insert_data(200, 400)

        # select with flush
        threads = []
        for _ in range(5):
            t = threading.Thread(target=self.select_and_count, args=(400,))
            threads.append(t)
            t.start()

        self.insert_data(0, 1000)

        # select
        self.select_and_count(1000)

    @unittest.skip("Not implemented yet")
    def test_flush_with_query_unorder_larger_test(self):
        # insert
        self.insert_data(0, 100)
        self.insert_data(500, 600)

        # select
        self.select_and_count(200)

        self.insert_data(200, 400)

        # select with flush
        threads = []
        for _ in range(5):
            t = threading.Thread(target=self.select_and_count, args=(400,))
            threads.append(t)
            t.start()

        self.insert_data(800, 1500)

        # select with flush
        for t in threads:
            t.join()
            t.start()

    @unittest.skip("Not implemented yet")
    def test_insert_with_query_together_test(self):
        query_thread_list = []

        cur = threading.Thread(target=self.insert_data, args=(0, 200,))
        query_thread_list.append(cur)
        cur.start()

        cur = threading.Thread(target=self.select_and_count, args=(100,))
        query_thread_list.append(cur)
        cur.start()

        cur = threading.Thread(target=self.insert_data, args=(200, 400,))
        query_thread_list.append(cur)
        cur.start()

        cur = threading.Thread(target=self.select_and_count, args=(300,))
        query_thread_list.append(cur)
        cur.start()

        cur = threading.Thread(target=self.flush,)
        query_thread_list.append(cur)
        cur.start()

        for thread in query_thread_list:
            thread.join()

    def select_with_multi_thread_and_flush(self, res):
        threads = []

        for _ in range(5):
            t = threading.Thread(target=self.select_and_count, args=(res,))
            threads.append(t)
            t.start()

        if _ == 2:
            flush_thread = threading.Thread(target=self.flush,)
            query_thread_list.append(flush_thread)
            flush_thread.start()

    def select_with_multi_thread(self, res):
        threads = []

        for _ in range(5):
            t = threading.Thread(target=self.select_and_count, args=(res,))
            threads.append(t)
            t.start()

        for thread in threads:
            thread.join()

    def insert_data(self, start, end):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            for time in range(start, end):
                sql = f"insert into root.fans.d0(timestamp,s0) values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d0(timestamp,s1) values({time},{time % 40})"
                cursor.execute(sql)

        except mysql.connector.Error as err:
            print(err)

    def flush(self):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            sql = "flush"
            cursor.execute(sql)

        except mysql.connector.Error as err:
            print(err)

    def select_and_count(self, res):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            sql = "select * from root.**"
            has_result_set = cursor.execute(sql)
            self.assertTrue(has_result_set)

        except mysql.connector.Error as err:
            print(err)


if __name__ == '__main__':
    unittest.main()
