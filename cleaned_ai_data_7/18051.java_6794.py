import iotdb.exceptions as exceptions

class InsertConsumer:
    def __init__(self):
        pass

    def insert(self, connection: 'SessionConnection', record) -> None:
        try:
            # Your logic here
            pass
        except (exceptions.IoTDBConnectionException,
                exceptions.StatementExecutionException,
                exceptions.RedirectException) as e:
            raise e
