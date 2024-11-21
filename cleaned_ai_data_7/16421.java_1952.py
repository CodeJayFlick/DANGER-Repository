import logging
from thrift import Thrift
from thrift.protocol import TBinaryProtocol
from thrift.server import TFramedTransport
from thrift.transport import TSocket
from iotdb.thrift.TSIService import TSIService, ClientFactory
from iotdb.thrift.TSCloseOperationReq import TSCloseOperationReq
from iotdb.thrift.TSExecuteStatementResp import TSExecuteStatementResp
from iotdb.thrift.TSInsertStringRecordReq import TSInsertStringRecordReq

class IoTDBClient:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.client = ClientFactory().getClient(TSocket.TSocket(ip, port), TBinaryProtocol.TBinaryProtocol())

    def connect_client(self):
        open_req = TSOpenSessionReq(0, "root", "root")
        resp = self.client.openSession(open_req)
        return resp.sessionId

    def execute_query(self, query_id, statement_id):
        req = TSExecuteStatementReq(query_id, query, statement_id).setFetchSize(1000)
        resp = self.client.executeQueryStatement(req)
        if resp.status.code != 0:
            failed_queries[query] = resp.status
            return

    def close_operation(self, session_id, query_id):
        req = TSCloseOperationReq(session_id)
        req.setQueryId(query_id)
        self.client.closeOperation(req)

def main():
    logging.basicConfig(level=logging.INFO)
    client = IoTDBClient("localhost", 6667)
    sessionId = client.connect_client()
    
    # test insertion
    for device in DEVICES:
        for measurement in MEASUREMENTS:
            req = TSInsertStringRecordReq().setMeasurements([measurement]).setSessionId(sessionId).setTimestamp(0)
            self.client.insertStringRecord(req)

if __name__ == "__main__":
    main()
