import logging
from typing import List

class StartupChecks:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.default_tests: List[StartupCheck] = []
        self.pre_checks: List[StartupCheck] = []

        self.add_default_tests()

    def add_default_tests(self):
        self.default_tests.append(JMXPortCheck())
        self.default_tests.append(JDKCheck())

    @property
    def default_tests(self) -> List[StartupCheck]:
        return self._default_tests

    @property
    def pre_checks(self) -> List[StartupCheck]:
        return self._pre_checks

    def with_default_test(self):
        self.pre_checks.extend(self.default_tests)
        return self

    class StartupCheck:
        def __init__(self, func: callable):
            self.func = func

        def execute(self):
            try:
                self.func()
            except Exception as e:
                raise StartupException(str(e))

class JMXPortCheck(StartupChecks.StartupCheck):
    def __call__(self):
        jmx_port = os.environ.get("IOTDB_JMX_PORT")
        if not jmx_port:
            self.logger.warning(f"IOTDB_JMX_PORT missing from {IoTDBConstant.ENV_FILE_NAME}.sh (Unix or OS X, if you use Windows, check conf/{IoTDBConstant.ENV_FILE_NAME}.bat)")
        else:
            self.logger.info(f"JMX is enabled to receive remote connection on port {jmx_port}")

class JDKCheck(StartupChecks.StartupCheck):
    def __call__(self):
        version = CommonUtils.get_jdk_version()
        if version < IoTDBConstant.MIN_SUPPORTED_JDK_VERSION:
            raise StartupException(f"Requires JDK version >= {IoTDBConstant.MIN_SUPPORTED_JDK_VERSION}, current version is {version}")
        else:
            self.logger.info(f"JDK version is {version}")

    def verify(self):
        for check in self.pre_checks:
            check.execute()
