import logging
from thrift import TException
from thrift.protocol import TProtocol
from thrift.server import TServer
from thrift.transport import TTransport
from iotdb.thrift import Node, PullSchemaResp
from tsfile.write.schema import IMeasurementSchema, UnaryMeasurementSchema, VectorMeasurementSchema

class PullMeasurementSchemaHandler:
    def __init__(self, owner: Node, prefix_paths: list[str], timeseries_schemas: 'atomic.AtomicReference[list[IMeasurementSchema]]'):
        self.owner = owner
        self.prefix_paths = prefix_paths
        self.timeseries_schemas = timeseries_schemas

    async def on_complete(self, response: PullSchemaResp):
        buffer = response.schema_bytes
        size = int.from_bytes(buffer[:4], 'big')
        schemas = []
        for _ in range(size):
            if buffer[0] == 0:
                schema = await UnaryMeasurementSchema.partial_deserialize_from(buffer)
            else:
                schema = await VectorMeasurementSchema.partial_deserialize_from(buffer)
            schemas.append(schema)
        with self.timeseries_schemas.get_lock():
            self.timeseries_schemas.value = schemas
            self.timeseries_schemas.notify_all()

    async def on_error(self, exception: Exception):
        logging.error("Cannot pull time series schema of {} from {}".format(', '.join(self.prefix_paths), self.owner))
        with self.timeseries_schemas.get_lock():
            self.timeseries_schemas.notify_all()
