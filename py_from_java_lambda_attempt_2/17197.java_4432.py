Here is the translation of the Java code to Python:
```
import metrics_registry
from jetty import Server, ServletContextHandler
from query_servlet import QueryServlet
from static_handler import StaticHandler

class MetricsWebUI:
    def __init__(self, metric_registry):
        self.metric_registry = metric_registry
        self.handlers = []

    @property
    def metric_registry(self):
        return self._metric_registry

    @metric_registry.setter
    def metric_registry(self, value):
        self._metric_registry = value

    @property
    def handlers(self):
        return self._handlers

    @handlers.setter
    def handlers(self, value):
        self._handlers = value

    def initialize(self):
        master_page = MetricsPage(self.metric_registry)
        query_servlet = QueryServlet(master_page)
        static_handler = StaticHandler()
        query_handler = ServletContextHandler("/", query_servlet)
        self.handlers.append(static_handler)
        self.handlers.append(query_handler)

    def get_server(self, port):
        return JettyUtil.get_jetty_server(self.handlers, port)
```
Note that I've assumed the following:

* `metrics_registry` is a Python module containing the equivalent of Java's `MetricRegistry`.
* `jetty`, `query_servlet`, and `static_handler` are Python modules containing the equivalent of Java's Jetty-related classes.
* The rest of the code remains largely unchanged, with some minor adjustments to accommodate Python's syntax and semantics.

Please note that this is just one possible translation, and there may be other ways to achieve the same result in Python.