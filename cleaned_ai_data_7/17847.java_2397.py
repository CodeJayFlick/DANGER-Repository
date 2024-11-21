import pyodbc
from datetime import datetime

class IoTDBLastIT:
    TIMESTAMP_STR = "Time"
    TIMESEIRES_STR = "timeseries"
    VALUE_STR = "value"
    DATA_TYPE_STR = "dataType"

    def setUp(self):
        conn_str = 'DRIVER={};SERVER=localhost;PORT=6667;DATABASE=root;UID=root;PWD=root'.format('com.mysql.cj.jdbc.Driver')
        cnxn = pyodbc.connect(conn_str)
        cursor = cnxn.cursor()
        
        for sql in self.dataSet1:
            cursor.execute(sql)

        for sql in self.dataSet2:
            cursor.execute(sql)

        for sql in self.dataSet3:
            cursor.execute(sql)

    def tearDown(self):
        conn_str = 'DRIVER={};SERVER=localhost;PORT=6667;DATABASE=root;UID=root;PWD=root'.format('com.mysql.cj.jdbc.Driver')
        cnxn = pyodbc.connect(conn_str)
        cursor = cnxn.cursor()
        
        for sql in self.dataSet1:
            cursor.execute(sql)

    def lastWithEmptySeriesTest(self):
        retArray = ["root.ln.wf02.status,true,BOOLEAN"]
        
        conn_str = 'DRIVER={};SERVER=localhost;PORT=6667;DATABASE=root;UID=root;PWD=root'.format('com.mysql.cj.jdbc.Driver')
        cnxn = pyodbc.connect(conn_str)
        cursor = cnxn.cursor()
        
        for sql in self.dataSet1:
            cursor.execute(sql)

        for sql in self.dataSet2:
            cursor.execute(sql)

        for sql in self.dataSet3:
            cursor.execute(sql)

        hasResultSet = False
        try:
            result = cursor.execute("select last * from root.** order by time desc")
            hasResultSet = True
        except pyodbc.Error as e:
            print(f"Error: {e}")

    def lastDescTimeTest(self):
        retArray = ["500,root.ln.wf01.wt01.temperature,22.1,DOUBLE", "500,root.ln.wf01.wt02.temperature,15.7,DOUBLE"]
        
        conn_str = 'DRIVER={};SERVER=localhost;PORT=6667;DATABASE=root;UID=root;PWD=root'.format('com.mysql.cj.jdbc.Driver')
        cnxn = pyodbc.connect(conn_str)
        cursor = cnxn.cursor()
        
        for sql in self.dataSet1:
            cursor.execute(sql)

        for sql in self.dataSet2:
            cursor.execute(sql)

        for sql in self.dataSet3:
            cursor.execute(sql)

    def lastCacheUpdateTest(self):
        retArray = ["500,root.ln.wf01.wt01.temperature,22.1,DOUBLE", "700,root.ln.wf01.wt01.temperature,33.1,DOUBLE"]
        
        conn_str = 'DRIVER={};SERVER=localhost;PORT=6667;DATABASE=root;UID=root;PWD=root'.format('com.mysql.cj.jdbc.Driver')
        cnxn = pyodbc.connect(conn_str)
        cursor = cnxn.cursor()
        
        for sql in self.dataSet1:
            cursor.execute(sql)

    def lastWithUnSeqFilesTest(self):
        retArray = ["500,root.ln.wf01.wt02.temperature,15.7,DOUBLE", "600,root.ln.wf01.wt02.temperature,10.2,DOUBLE"]
        
        conn_str = 'DRIVER={};SERVER=localhost;PORT=6667;DATABASE=root;UID=root;PWD=root'.format('com.mysql.cj.jdbc.Driver')
        cnxn = pyodbc.connect(conn_str)
        cursor = cnxn.cursor()
        
        for sql in self.dataSet1:
            cursor.execute(sql)

    def lastWithEmptyChunkMetadataTest(self):
        retArray = ["300,root.ln.wf01.wt03.temperature,23.1,DOUBLE"]
        
        conn_str = 'DRIVER={};SERVER=localhost;PORT=6667;DATABASE=root;UID=root;PWD=root'.format('com.mysql.cj.jdbc.Driver')
        cnxn = pyodbc.connect(conn_str)
        cursor = cnxn.cursor()
        
        for sql in self.dataSet1:
            cursor.execute(sql)

    def lastWithUnseqTimeLargerThanSeqTimeTest(self):
        retArray = ["150,root.ln.wf01.wt04.temperature,31.2,DOUBLE"]
        
        conn_str = 'DRIVER={};SERVER=localhost;PORT=6667;DATABASE=root;UID=root;PWD=root'.format('com.mysql.cj.jdbc.Driver')
        cnxn = pyodbc.connect(conn_str)
        cursor = cnxn.cursor()
        
        for sql in self.dataSet1:
            cursor.execute(sql)

    def lastAfterDeletionTest(self):
        retArray = ["350,root.ln.wf01.wt05.temperature,31.2,DOUBLE", "200,root.ln.wf01.wt05.temperature,78.2,DOUBLE"]
        
        conn_str = 'DRIVER={};SERVER=localhost;PORT=6667;DATABASE=root;UID=root;PWD=root'.format('com.mysql.cj.jdbc.Driver')
        cnxn = pyodbc.connect(conn_str)
        cursor = cnxn.cursor()
        
        for sql in self.dataSet1:
            cursor.execute(sql)

    def lastWithFilterTest(self):
        retArray = ["500,root.ln.wf01.wt01.temperature,22.1,DOUBLE"]
        
        conn_str = 'DRIVER={};SERVER=localhost;PORT=6667;DATABASE=root;UID=root;PWD=root'.format('com.mysql.cj.jdbc.Driver')
        cnxn = pyodbc.connect(conn_str)
        cursor = cnxn.cursor()
        
        for sql in self.dataSet1:
            cursor.execute(sql)

    def prepareData(self):
        conn_str = 'DRIVER={};SERVER=localhost;PORT=6667;DATABASE=root;UID=root;PWD=root'.format('com.mysql.cj.jdbc.Driver')
        cnxn = pyodbc.connect(conn_str)
        cursor = cnxn.cursor()
        
        for sql in self.dataSet1:
            cursor.execute(sql)

    dataSet1 = [
        "CREATE TIMESERIES root.ln.wf01.wt01.status WITH DATATYPE=BOOLEAN, ENCODING=PLAIN",
        "CREATE TIMESERIES root.ln.wf01.wt01.temperature WITH DATATYPE=DOUBLE, ENCODING=PLAIN",
        "INSERT INTO root.ln.wf01.wt01( timestamp, temperature) values (100, 25.1)",
        "INSERT INTO root.ln.wf01.wt01(timestamp,temperature,status,id) values(200, 25.2,true,8)",
        "INSERT INTO root.ln.wf01.wt01(timestamp,temperature,status,id) values(300,15.7,false,9)",
        "INSERT INTO root.ln.wf01.wt01(timestamp,temperature,status,id) values(400,16.2,false,6)",
        "INSERT INTO root.ln.wf01.wt01(timestamp,temperature,status,id) values(500,22.1,false,5)"
    ]

    dataSet2 = [
        "CREATE TIMESERIES root.ln.wf01.wt02.status WITH DATATYPE=BOOLEAN, ENCODING=PLAIN",
        "CREATE TIMESERIES root.ln.wf01.wt02.temperature WITH DATATYPE=DOUBLE, ENCODING=PLAIN",
        "INSERT INTO root.ln.wf01.wt02(timestamp,status) values(100,true)",
        "INSERT INTO root.ln.wf01.wt02(timestamp,temperature,status,id) values(300,23.1,true,8)"
    ]

    dataSet3 = [
        "CREATE TIMESERIES root.ln.wf01.wt03.status WITH DATATYPE=BOOLEAN, ENCODING=PLAIN",
        "INSERT INTO root.ln.wf01.wt03(timestamp,status) values(100,false)",
        "flush"
    ]
