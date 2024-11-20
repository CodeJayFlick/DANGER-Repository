import re
from threading import AtomicInteger
import subprocess
import logging

class FlapdoodleMongoTestConnectionProviderSource:
    LISTEN_ON_PORT_PATTERN = re.compile(r".*NETWORK \(([^\\n]*)\)\s+waiting\s+for\s+connections\s+on\s+port\s+(\d+)\n.*", re.MULTILINE | re.DOTALL)

    def __init__(self):
        self.port = AtomicInteger(0)
        self.mongo = None

    def start(self) -> None:
        if self.mongo is not None:
            raise ValueError("Already started")

        default_output = subprocess.PIPE
        captured_stdout = logging.StreamHandler()
        buffer = ""

        class StreamProcessor(logging.Handler):
            def handle(self, record: logging.LogRecord) -> None:
                nonlocal buffer
                buffer += str(record.msg)
                matcher = self.LISTEN_ON_PORT_PATTERN.match(buffer)
                if matcher is not None:
                    port_string = matcher.group(2)
                    self.port.set(int(port_string))
                default_output.write(str(record.msg))

            def flush(self) -> None:
                pass

        captured_stdout.setFormatter(logging.Formatter())
        logging.basicConfig(level=logging.INFO, handlers=[captured_stdout])

        starter = MongodStarter()
        mongod_config = MongodConfig(version=MongodVersion.PRODUCTION)
        net = Net(0, Network.localhost_is_ipv6())

        self.mongo = starter.prepare(mongod_config.build(), net.build())
        self.mongo.start()

        assert self.port.get() > 0

        connection_string = f"mongodb://localhost:{self.port.get()}"

    def stop(self) -> None:
        try:
            super().stop()
        finally:
            if self.mongo is not None:
                self.mongo.stop()
            self.mongo = None
