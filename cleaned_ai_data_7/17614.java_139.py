import logging
from jmx import MBeanServer, ObjectName

class JMXService:
    _logger = logging.getLogger(__name__)

    def __init__(self):
        pass

    @classmethod
    def get_instance(cls):
        return cls._instance

    _instance = None

    @staticmethod
    def register_mbean(mbean, name):
        try:
            mbs = MBeanServer()
            object_name = ObjectName(name)
            if not mbs.is_registered(object_name):
                mbs.register_mbean(mbean, object_name)
        except (MalformedObjectNameException,
                InstanceAlreadyExistsException,
                MBeanRegistrationException) as e:
            _logger.error("Failed to registerMBean %s", name, exc_info=e)

    @staticmethod
    def deregister_mbean(name):
        try:
            mbs = MBeanServer()
            object_name = ObjectName(name)
            if mbs.is_registered(object_name):
                mbs.unregister_mbean(object_name)
        except (MalformedObjectNameException,
                MBeanRegistrationException,
                InstanceNotFoundException) as e:
            _logger.error("Failed to unregisterMBean %s", name, exc_info=e)

    def get_id(self):
        return "JMX_SERVICE"

    def start(self):
        jmx_port = os.environ.get("IOTDB_JMX_PORT")
        if not jmx_port:
            self._logger.debug(f"{self.get_id()} JMX port is undefined")

    def stop(self):
        pass

class JMXServerHolder:
    _instance = None

    @classmethod
    def get_instance(cls):
        return cls._instance

    @staticmethod
    def __init__():
        if not JMXService._instance:
            JMXService._instance = JMXService()
