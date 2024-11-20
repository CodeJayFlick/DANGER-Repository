Here is the equivalent Python code:

```Python
class SqlArgument:
    def __init__(self,
                 ts_execute_statement_resp: 'TSExecuteStatementResp',
                 plan: 'PhysicalPlan',
                 statement: str,
                 start_time: int,
                 end_time: int):
        self.ts_execute_statement_resp = ts_execute_statement_resp
        self.plan = plan
        self.statement = statement
        self.start_time = start_time
        self.end_time = end_time

    @property
    def ts_execute_statement_resp(self) -> 'TSExecuteStatementResp':
        return self._ts_execute_statement_resp

    @ts_execute_statement_resp.setter
    def ts_execute_statement_resp(self, value: 'TSExecuteStatementResp'):
        self._ts_execute_statement_resp = value

    @property
    def start_time(self) -> int:
        return self._start_time

    @start_time.setter
    def start_time(self, value: int):
        self._start_time = value

    @property
    def end_time(self) -> int:
        return self._end_time

    @end_time.setter
    def end_time(self, value: int):
        self._end_time = value

    @property
    def plan(self) -> 'PhysicalPlan':
        return self._plan

    @plan.setter
    def plan(self, value: 'PhysicalPlan'):
        self._plan = value

    @property
    def statement(self) -> str:
        return self._statement

    @statement.setter
    def statement(self, value: str):
        self._statement = value


class TSExecuteStatementResp:
    pass  # You need to define this class or use an existing one


class PhysicalPlan:
    pass  # You need to define this class or use an existing one
```