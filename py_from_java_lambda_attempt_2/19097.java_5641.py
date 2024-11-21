Here is the translation of the given Java code into equivalent Python:

```Python
import logging
from typing import Any, Dict, List

class TxConnectionProvider:
    def __init__(self):
        self.setup_done = False
        self.config = None
        self.logger = logging.getLogger(__name__)

    def configure(self, config: Any) -> None:
        self.config = config

    def initialize(self) -> None:
        pass  # No equivalent in Python

    def setup_database(self, adapter: Any) -> None:
        if not self.setup_done:
            try:
                conn = self.borrow_connection()
                st = conn.cursor()

                metadata_upper_case = adapter.metadata_upper_case
                catalog = config.get_catalog()
                schema = config.get_schema()
                data_types = adapter.database_sql_format_parameters

                format_params_array = [data_types[dt] for dt in NessieSqlDataType]

                ddls = (ddl for ddl, _ in adapter.all_create_table_ddl().items() if not self.table_exists(conn, metadata_upper_case, catalog, schema, ddl))
                execute_ddls(adapter.batch_ddl(), ddls, st)

            except Exception as e:
                raise RuntimeError(e)
            finally:
                conn.close()
                self.setup_done = True

    def borrow_connection(self) -> Any:
        # This method should be implemented in the subclass
        pass  # No equivalent in Python

    @staticmethod
    def execute_ddls(batch_ddl: bool, ddls: List[str], st):
        if batch_ddl:
            ddl = '\n'.join(ddls)
            if ddl:
                ddl = 'BEGIN;\n' + ddl + '\nEND TRANSACTION;\n'
                logging.debug('Executing DDL batch\n{}'.format(ddl))
                st.execute(ddl)
        else:
            for ddl in ddls:
                logging.debug('Executing DDL: {}'.format(ddl))
                st.execute(ddl)

    @staticmethod
    def table_exists(conn, metadata_upper_case, catalog, schema, table):
        if metadata_upper_case:
            catalog = catalog.upper() if catalog is not None else None
            schema = schema.upper() if schema is not None else None
            table = table.upper() if table is not None else None

        try:
            tables = conn.cursor().execute('SELECT * FROM information_schema.tables WHERE TABLE_NAME=?', (table,))
            return next(tables, False)
        except Exception as e:
            raise RuntimeError(e)

class NessieSqlDataType:
    # This class should be implemented in the subclass
    pass  # No equivalent in Python

# You can use this code like this:

adapter = TxConnectionProvider()
adapter.configure(config)