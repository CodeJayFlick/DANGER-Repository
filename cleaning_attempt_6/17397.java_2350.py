import logging
from concurrent.futures import ThreadPoolExecutor, scheduled
from typing import Dict, Any

class QueryTimeManager:
    def __init__(self):
        self.query_context_map: Dict[int, dict] = {}
        self.executor_service: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=1)
        self.query_scheduled_task_map: Dict[int, Any] = {}

    def register_query(self, context: dict) -> None:
        query_id = context['queryId']
        if query_id not in self.query_context_map:
            self.query_context_map[query_id] = context
            if 'timeout' in context and context['timeout'] < 0:
                context['timeout'] = IoTDBDescriptor.getInstance().getConfig()['queryTimeoutThreshold']
            if 'timeout' in context and context['timeout'] != 0:
                scheduled_future: Any = self.executor_service.schedule(
                    lambda: self.kill_query(query_id),
                    context['timeout'],
                    milliseconds=True
                )
                self.query_scheduled_task_map[query_id] = scheduled_future

    def kill_query(self, query_id: int) -> None:
        if query_id in self.query_context_map and 'interrupted' not in self.query_context_map[query_id]:
            self.query_context_map[query_id]['interrupted'] = True
            logging.warning(f"Query is time out ({context['timeout']}ms) with queryId {query_id}")

    def unregister_query(self, query_id: int, full_quit: bool) -> None:
        if query_id in self.query_context_map and 'interrupted' not in self.query_context_map[query_id]:
            del self.query_context_map[query_id]
            scheduled_future = self.query_scheduled_task_map.pop(query_id)
            if scheduled_future is not None:
                scheduled_future.cancel()
            SessionTimeoutManager.getInstance().refresh(SessionManager.getInstance().getSessionIdByQueryId(query_id))

    @staticmethod
    def check_query_alive(query_id: int) -> bool:
        query_context = QueryTimeManager.getInstance().get_query_context_map().get(query_id)
        if query_context is None or 'interrupted' in query_context and query_context['interrupted']:
            return False
        else:
            return True

    @property
    def query_context_map(self):
        return self._query_context_map

    @query_context_map.setter
    def query_context_map(self, value: Dict[int, dict]):
        self._query_context_map = value

    @property
    def executor_service(self):
        return self._executor_service

    @executor_service.setter
    def executor_service(self, value: ThreadPoolExecutor):
        self._executor_service = value

    @property
    def query_scheduled_task_map(self):
        return self._query_scheduled_task_map

    @query_scheduled_task_map.setter
    def query_scheduled_task_map(self, value: Dict[int, Any]):
        self._query_scheduled_task_map = value


class QueryTimeManagerHelper:
    INSTANCE = QueryTimeManager()


def main():
    logging.basicConfig(level=logging.INFO)
    manager = QueryTimeManager()
    # Your code here

if __name__ == "__main__":
    main()

