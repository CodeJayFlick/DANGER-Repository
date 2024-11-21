Here is the translation of the Java code into Python:

```Python
import unittest
from thrift import Thrift
from thrift.protocol import TProtocol
from thrift.transport import TTransport
from thrift.server import TServer
from org.apache.thrift.TException import TException
from org.apache.thrift. TSExecuteStatementReq import TSExecuteStatementReq

class IoTDBDatabaseMetadataTest(unittest.TestCase):

    def setUp(self):
        self.queryId = 1L
        self.sessionId = 2L
        self.resp = None
        self.properties = None
        self.execStatementResp = None
        self.client = None
        self.connection = None
        self.statement = None
        self.databaseMetaData = None

    def testGetAttributes(self):
        result_set = self.databaseMetaData.getExportedKeys(None, None, None)
        self.assertEqual("Time", result_set.metaData.columns[0].name)

    def testGetBestRowIdentifier(self):
        result_set = self.databaseMetaData.getBestRowIdentifier(None, None, None, 0, True)
        self.assertEqual("Time", result_set.metaData.columns[1].name)

    def testGetCatalogs(self):
        statement = self.connection.createStatement()
        resp = RpcUtils.getStatus([TSStatusCode.SUCCESS_STATUS])
        when(client.executeBatchStatement(any(TSExecuteBatchStatementReq.class))).thenReturn(resp)
        expected_result = [RpcUtils.getStatus( TSStatusCode.SUCCESS_STATUS ) for _ in range(2)]
        resp.setSubStatus(expected_result)

    def testGetImportedKeys(self):
        result_set = self.databaseMetaData.getImportedKeys(None, None, None)
        self.assertEqual("Time", result_set.metaData.columns[0].name)

    def testGetIndexInfo(self):
        result_set = self.databaseMetaData.getIndexInfo(None, None, None, False, False)
        self.assertEqual("Time", result_set.metaData.columns[1].name)


if __name__ == '__main__':
   unittest.main()
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific environment.