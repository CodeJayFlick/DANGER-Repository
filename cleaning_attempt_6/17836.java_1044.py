import datetime as dt
from pyiotdb import IoTDBConnection
from sqlalchemy import create_engine, text

class IoTDBGroupByMonthIT:
    TIMESTAMP_STR = "Time"
    df = dt.datetime.strptime("MM/dd/yyyy:HH:mm:ss", "%m/%d/%Y:%H:%M:%S")

    @classmethod
    def setUp(cls):
        cls.df.tzinfo = dt.timezone(dt.timedelta(hours=0))
        IoTDBConnection.set_timezone("GMT+00:00")
        prepare_data()

    @classmethod
    def tearDown(cls):
        IoTDBConnection.clean_env()

    @staticmethod
    def group_by_natural_month1():
        try:
            conn = create_engine("jdbc:iotdb://127.0.0.1:6667/").connect()
            with conn.begin() as transaction:
                result = transaction.execute(text("""
                    SELECT SUM(temperature) FROM root.sg1.d1
                    GROUP BY ([1604102400000, 1614556800000), 1mo, 1mo)
                """))
                ret_array1 = ["10/31/2020:00:00:00", "30.0",
                              "11/30/2020:00:00:00", "31.0",
                              "12/31/2020:00:00:00", "31.0",
                              "01/31/2021:00:00:00", "28.0",
                              "02/28/2021:00:00:00", "1.0"]
                cnt = 0
                for row in result:
                    time = row[TIMESTAMP_STR]
                    ans = str(row["SUM(temperature)"])
                    assert ret_array1[cnt] == df.strftime(dt.datetime.strptime(time, "%m/%d/%Y:%H:%M:%S"))
                    assert ans == ret_array1[cnt + 1]
                    cnt += 2
                assert len(ret_array1) == cnt

        except Exception as e:
            print(e)
            fail()

    @staticmethod
    def group_by_natural_month2():
        try:
            conn = create_engine("jdbc:iotdb://127.0.0.1:6667/").connect()
            with conn.begin() as transaction:
                result = transaction.execute(text("""
                    SELECT SUM(temperature) FROM root.sg1.d1
                    GROUP BY ([1604102400000, 1614556800000), 10d, 1mo)
                """))
                ret_array1 = ["10/31/2020:00:00:00", "10.0",
                              "11/30/2020:00:00:00", "10.0",
                              "12/31/2020:00:00:00", "10.0",
                              "01/31/2021:00:00:00", "10.0",
                              "02/28/2021:00:00:00", "1.0"]
                cnt = 0
                for row in result:
                    time = row[TIMESTAMP_STR]
                    ans = str(row["SUM(temperature)"])
                    assert ret_array1[cnt] == df.strftime(dt.datetime.strptime(time, "%m/%d/%Y:%H:%M:%S"))
                    assert ans == ret_array1[cnt + 1]
                    cnt += 2
                assert len(ret_array1) == cnt

        except Exception as e:
            print(e)
            fail()

    @staticmethod
    def group_by_natural_month3():
        try:
            conn = create_engine("jdbc:iotdb://127.0.0.1:6667/").connect()
            with conn.begin() as transaction:
                result = transaction.execute(text("""
                    SELECT SUM(temperature) FROM root.sg1.d1
                    GROUP BY ([1604102400000, 1606694400000), 1mo)
                """))
                cnt = 0
                for row in result:
                    cnt += 1

        except Exception as e:
            print(e)
            fail()

    @staticmethod
    def group_by_natural_month4():
        try:
            conn = create_engine("jdbc:iotdb://127.0.0.1:6667/").connect()
            with conn.begin() as transaction:
                result = transaction.execute(text("""
                    SELECT SUM(temperature) FROM root.sg1.d1
                    GROUP BY ([1612051200000, 1617148800000), 1mo)
                """))
                ret_array1 = ["01/31/2021:00:00:00", "28.0",
                              "02/28/2021:00:00:00", "31.0"]
                cnt = 0
                for row in result:
                    time = row[TIMESTAMP_STR]
                    ans = str(row["SUM(temperature)"])
                    assert ret_array1[cnt] == df.strftime(dt.datetime.strptime(time, "%m/%d/%Y:%H:%M:%S"))
                    assert ans == ret_array1[cnt + 1]
                    cnt += 2
                assert len(ret_array1) == cnt

        except Exception as e:
            print(e)
            fail()

    @staticmethod
    def group_by_natural_month5():
        try:
            conn = create_engine("jdbc:iotdb://127.0.0.1:6667/").connect()
            with conn.begin() as transaction:
                result = transaction.execute(text("""
                    SELECT SUM(temperature) FROM root.sg1.d1
                    GROUP BY ([1612051200000, 1617148800000), 1mo)
                    ORDER BY time DESC
                """))
            fail("No Exception thrown")

        except Exception as e:
            assert str(e).contains("doesn't support order by time desc now.")

    @staticmethod
    def group_by_natural_month6():
        try:
            conn = create_engine("jdbc:iotdb://127.0.0.1:6667/").connect()
            with conn.begin() as transaction:
                result = transaction.execute(text("""
                    SELECT SUM(temperature) FROM root.sg1.d1
                    GROUP BY ([now() - 1mo, now()), 1d)
                """))
                cnt = 0
                times = []
                for row in result:
                    ans = str(row["SUM(temperature)"])
                    if ans == "0.0":
                        cnt += 1
                    times.append(str(row[TIMESTAMP_STR]))
                assert cnt >= 28 and cnt <= 31

        except Exception as e:
            print(e)
            fail()

    @staticmethod
    def prepare_data():
        try:
            conn = create_engine("jdbc:iotdb://127.0.0.1:6667/").connect()
            with conn.begin() as transaction:
                for i in range(1604102400000, 1617148800000):
                    transaction.execute(text(f"INSERT INTO root.sg1.d1(timestamp, temperature) VALUES ({i}, 1)"))

        except Exception as e:
            print(e)

IoTDBGroupByMonthIT.setUp()
