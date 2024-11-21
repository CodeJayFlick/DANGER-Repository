import mysql.connector
from datetime import datetime, timedelta

class IoTDBUDTFHybridQueryIT:
    ACCESS_STRATEGY_KEY = "access"
    ACCESS_STRATEGY_ROW_BY_ROW = "row-by-row"

    def setUp(self):
        self.env_setup()
        self.create_time_series()
        self.generate_data()
        self.register_udf()

    def tearDown(self):
        self.clean_env()

    def env_setup(self):
        pass

    def clean_env(self):
        pass

    def create_time_series(self):
        # Create timeseries
        meta_manager = IoTDB.metaManager
        meta_manager.set_storage_group(PartialPath("root.vehicle"))
        meta_manager.create_timeseries(
            PartialPath("root.vehicle.d1.s1"), TSDataType.INT32, TSEncoding.PLAIN,
            CompressionType.UNCOMPRESSED, None)
        meta_manager.create_timeseries(
            PartialPath("root.vehicle.d1.s2"), TSDataType.INT32, TSEncoding.PLAIN,
            CompressionType.UNCOMPRESSED, None)

    def generate_data(self):
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1", user="root", password="root")
            cursor = connection.cursor()
            for i in range(10):
                cursor.execute(f"insert into root.vehicle.d1(timestamp,s1,s2) values({i},{i},{i})")
        except mysql.connector.Error as e:
            print(e)

    def register_udf(self):
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1", user="root", password="root")
            cursor = connection.cursor()
            cursor.execute("create function counter as 'org.apache.iotdb.db.query.udf.example.Counter'")
        except mysql.connector.Error as e:
            print(e)

    def test_user_defined_built_in_hybrid_aggregation_query(self):
        sql = f"select count(*), counter(s1, '{self.ACCESS_STRATEGY_KEY}'='{self.ACCESS_STRATEGY_ROW_BY_ROW}') from root.vehicle.d1"
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1", user="root", password="root")
            cursor = connection.cursor()
            cursor.execute(sql)
            print(cursor.fetchall())
        except mysql.connector.Error as e:
            assert str(e).contains("User-defined and built-in hybrid aggregation is not supported together.")

    def test_user_defined_function_fill_function_hybrid_query(self):
        sql = f"select temperature, counter(temperature, '{self.ACCESS_STRATEGY_KEY}'='{self.ACCESS_STRATEGY_ROW_BY_ROW}') from root.sgcc.wf03.wt01 where time = '2017-11-01T16:37:50.000' fill(float [linear, 1m, 1m])"
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1", user="root", password="root")
            cursor = connection.cursor()
            cursor.execute(sql)
            print(cursor.fetchall())
        except mysql.connector.Error as e:
            assert str(e).contains("Fill functions are not supported in UDF queries.")

    def test_last_user_defined_function_query(self):
        sql = f"select last counter(temperature, '{self.ACCESS_STRATEGY_KEY}'='{self.ACCESS_STRATEGY_ROW_BY_ROW}') from root.sgcc.wf03.wt01"
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1", user="root", password="root")
            cursor = connection.cursor()
            cursor.execute(sql)
            print(cursor.fetchall())
        except mysql.connector.Error as e:
            assert str(e).contains("Last queries can only be applied on raw time series.")

    def test_user_defined_function_align_by_device_query(self):
        sql = f"select adder(temperature), counter(temperature, '{self.ACCESS_STRATEGY_KEY}'='{self.ACCESS_STRATEGY_ROW_BY_ROW}') from root.sgcc.wf03.wt01 align by device"
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1", user="root", password="root")
            cursor = connection.cursor()
            cursor.execute(sql)
            print(cursor.fetchall())
        except mysql.connector.Error as e:
            assert str(e).contains("ALIGN BY DEVICE clause is not supported in UDF queries.")
