Here is the translation of the Java code into Python:

```Python
import unittest
from unittest.mock import patch, Mock
from thrift.TException import TTransportException

class BatchTest(unittest.TestCase):

    @patch('org.apache.iotdb.rpc.RpcUtils.getStatus')
    def setUp(self, mock_rpc_utils):
        self.connection = Mock()
        self.client = Mock()
        self.session_id = 0
        self.statement = Mock()

    def test_execute_batch_sql1(self):
        statement = self.connection.createStatement()
        statement.addBatch("sql1")
        resp = RpcUtils.getStatus([TSStatusCode.SUCCESS_STATUS])
        self.client.executeBatchStatement.return_value = resp

        result = statement.executeBatch()
        self.assertEqual(len(result), 1)

        res_expected = [RpcUtils.getStatus(TSStatusCode.SUCCESS_STATUS) for _ in range(10)]
        resp.setSubStatus(res_expected)
        
        statement.clearBatch()
        statement.addBatch("SET STORAGE GROUP TO root.ln.wf01.wt01")
        statement.addBatch("CREATE TIMESERIES root.ln wf01 wt01.status WITH DATATYPE=BOOLEAN, ENCODING=PLAIN")
        statement.addBatch("CREATE TIMESERIES root.ln wf01 wt01.temperature WITH DATATYPE=FLOAT, ENCODING=RLE")
        statement.addBatch("insert into root. ln.wf01.wt01(timestamp,status) values(1509465600000,true)")
        statement.addBatch("insert into root.ln wf01 wt01(timestamp,status) values(1509465660000,true)")
        statement.addBatch("insert into root.ln wf01 wt01(timestamp,temperature) values(1509465720000,25.957603)")
        result = statement.executeBatch()
        self.assertEqual(len(result), len(res_expected))
        for i in range(len(res_expected)):
            self.assertEqual(res_expected[i].code, result[i])

    @patch('org.apache.iotdb.rpc.RpcUtils.getStatus')
    def test_execute_batch_sql2(self):
        statement = self.connection.createStatement()
        resp = RpcUtils.getStatus([TSStatusCode.SQL_PARSE_ERROR])
        self.client.executeBatchStatement.return_value = resp

        with self.assertRaises(BatchUpdateException):
            statement.executeBatch()

    @patch('org.apache.iotdb.rpc.RpcUtils.getStatus')
    def test_execute_batch_sql3(self):
        statement = self.connection.createStatement()
        resp = RpcUtils.getStatus([TSStatusCode.INTERNAL_SERVER_ERROR, TSStatusCode.SQL_PARSE_ERROR])
        self.client.executeBatchStatement.return_value = resp

        try:
            result = statement.executeBatch()
        except BatchUpdateException as e:
            update_counts = e.getUpdateCounts()
            for i in range(len(resp.getSubStatus())):
                self.assertEqual(resp.getSubStatus()[i].code, update_counts[i])
        else:
            self.fail()

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Before` and `@After` annotations. Instead, you would typically use the setup method of your test class or the setUp() method provided by the unittest framework in Python.

Also note that I've used Python's built-in unit testing module (`unittest`) for this translation.