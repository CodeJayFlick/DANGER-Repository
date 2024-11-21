Here is the translation of the Java code into Python:

```Python
import pyodbc
from unittest import TestCase


class IoTDBExecuteBatchIT(TestCase):
    def setUp(self):
        EnvironmentUtils.envSetUp()

    def tearDown(self):
        EnvironmentUtils.cleanEnv()

    def testJDBCExecuteBatch(self):
        try:
            conn = pyodbc.connect('DRIVER={};SERVER=127.0.0.1:6667;DATABASE=root;UID=root;PWD=root'.format(Config.JDBC_ DRIVER_NAME))
            cursor = conn.cursor()
            cursor.execute("insert into root.ln.wf01.wt01(timestamp,temperature) values(1509465600000, 1.2)")
            cursor.addBatch("insert into root.ln wf01 wt01(timestamp, temperature) values(1509465600001, 2.3)")
            cursor.addBatch("delete timeseries root.ln wf01 wt01.*")
            cursor.addBatch("insert into root.ln wf01 wt01(timestamp, temperature) values(1509465600002, 3.4)")
            cursor.executeBatch()
            result = cursor.execute("select * from root.ln wf01 wt01").fetchall()

        except pyodbc.Error as e:
            self.fail(e)

    def testJDBCExecuteBatchForCreateMultiTimeSeriesPlan(self):
        try:
            conn = pyodbc.connect('DRIVER={};SERVER=127.0.0.1:6667;DATABASE=root;UID=root;PWD=root'.format(Config.JDBC_ DRIVER_NAME))
            cursor = conn.cursor()
            cursor.execute("insert into root.ln wf01 wt01(timestamp, temperature) values(1509465600000, 1.2)")
            cursor.addBatch("insert into root.ln wf01 wt01(timestamp, temperature) values(1509465600001, 2.3)")
            cursor.addBatch("delete timeseries root.ln wf01 wt01.*")
            cursor.addBatch("create timeseries root.turbine.d1.s1(s1) with datatype=boolean, encoding=plain, compression=snappy tags(tag1=v1, tag2=v2) attributes(attr1=v3, attr2=v4)")
            cursor.addBatch("create timeseries root.turbine.d1.s2(s2) with datatype=float, encoding=rle, compression=uncompressed tags(tag1=v5, tag2=v6) attributes(attr1=v7, attr2=v8)")
            cursor.addBatch("insert into root.ln wf01 wt01(timestamp, temperature) values(1509465600002, 3.4)")
            cursor.addBatch("create timeseries root.turbine.d1.s3 with datatype=boolean, encoding=rle")
            cursor.executeBatch()
            result = cursor.execute("select * from root.ln wf01 wt01").fetchall()

        except pyodbc.Error as e:
            self.fail(e)
```

Please note that the `EnvironmentUtils` class and the `Config.JDBC_ DRIVER_NAME` are not defined in this code. You would need to implement these classes or variables according to your requirements.