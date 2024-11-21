import collections
from metrics import MetricRegistry
from jetty.servlet import ServletContextHandler
from sink import MetricsServletSink
from source import MetricsSource

class MetricsSystem:
    def __init__(self, server_argument):
        self.sinks = []
        self.sources = []
        self.metric_registry = MetricRegistry()
        self.server_argument = server_argument

    @property
    def server_argument(self):
        return self._server_argument

    @server_argument.setter
    def server_argument(self, value):
        self._server_argument = value

    @property
    def metric_registry(self):
        return self._metric_registry

    @metric_registry.setter
    def metric_registry(self, value):
        self._metric_registry = value

    def get_server_context_handler(self):
        return MetricsServletSink(self.metric_registry).get_handler()

    def start(self):
        self.register_source()
        self.register_sinks()
        for sink in self.sinks:
            sink.start()

    def stop(self):
        for sink in self.sinks:
            sink.stop()

    def report(self):
        for sink in self.sinks:
            sink.report()

    def register_source(self):
        source = MetricsSource(self.server_argument, self.metric_registry)
        source.register_info()
        self.sources.append(source)

    def register_sinks(self):
        pass
