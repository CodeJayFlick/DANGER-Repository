import time
from codahale_metrics import MetricRegistry, ConsoleReporter

class ConsoleSink:
    def __init__(self, registry):
        self.registry = registry
        self.reporter = ConsoleReporter(registry)
            .convert_durations_to(timeunit.Milliseconds())
            .convert_rates_to(timeunit.Seconds())
            .build()

    def start(self):
        self.reporter.start(10)

    def stop(self):
        self.reporter.stop()

    def report(self):
        self.reporter.report()
