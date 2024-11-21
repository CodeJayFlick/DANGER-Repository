import pyodbc
from datetime import datetime as dt

class IoTDBMultiOverlappedPageIT:
    before_max_number_of_points_in_page = None
    before_memtable_size_threshold = None

    def setUpClass():
        global before_max_number_of_points_in_page, before_memtable_size_threshold
        try:
            # setup environment and database connection
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            
            before_max_number_of_points_in_page = IoTDBDescriptor.getInstance().getConfig().getMaxNumberOfPointsInPage()
            TSFileDescriptor.getInstance().getConfig().setMaxNumberOfPointsInPage(10)
            EnvironmentUtils.envSetUp()

        except Exception as e:
            print(e)

    def tearDownClass():
        try:
            # tear down environment and database connection
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            
            TSFileDescriptor.getInstance().getConfig().setMaxNumberOfPointsInPage(before_max_number_of_points_in_page)
            IoTDBDescriptor.getInstance().getConfig().setMemtableSizeThreshold(before_memtable_size_threshold)

        except Exception as e:
            print(e)

    @staticmethod
    def insert_data():
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()

            # create timeseries and insert data
            cursor.execute("CREATE TIMESERIES root.vehicle.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE")
            
            for time in range(1, 11):
                sql = f"insert into root.vehicle.d0(timestamp,s0) values({time},{time})"
                cursor.execute(sql)
                
            for time in range(11, 21):
                sql = f"insert into root.vehicle.d0(timestamp,s0) values({time},{100+time})"
                cursor.execute(sql)

            for time in range(1, 31):
                sql = f"insert into root.vehicle.d0(timestamp,s0) values({time},{time})"
                cursor.execute(sql)
            
            conn.commit()
            conn.close()

        except Exception as e:
            print(e)

    @staticmethod
    def select_overlapped_page_test():
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()

            sql = "select s0 from root.vehicle.d0 where time >= 1 and time <= 50 AND root.vehicle.d0.s0 >= 111"
            result = []
            
            for row in cursor.execute(sql):
                result.append(f"{row[0]},{row[1]}")

        except Exception as e:
            print(e)

    @staticmethod
    def select_overlapped_page_test2():
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()

            sql = "select first_value(s0) from root.vehicle.d0 where time > 18"
            
            result = []
            
            for row in cursor.execute(sql):
                result.append(f"{row[0]}")

        except Exception as e:
            print(e)

IoTDBMultiOverlappedPageIT.setUpClass()
IoTDBMultiOverlappedPageIT.insert_data()

# test select overlapped page
print(IoTDBMultiOverlappedPageIT.select_overlapped_page_test())

# test select overlapped page 2
print(IoTDBMultiOverlappedPageIT.select_overlapped_page_test2())
