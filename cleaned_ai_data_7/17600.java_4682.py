import logging
from concurrent.futures import ThreadPoolExecutor
from threading import Lock, RLock
from collections import defaultdict

class UDFRegistrationService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.registration_lock = Lock()
        self.registration_info = defaultdict(dict)
        self.log_writer_lock = RLock()
        self.log_writer = None

    def acquire_registration_lock(self):
        with self.registration_lock:
            pass

    def release_registration_lock(self):
        with self.registration_lock:
            pass

    def register(self, function_name: str, class_name: str, write_to_temporary_logfile=False) -> None:
        if not SQLConstant.get_native_function_names().contains(function_name.lower()):
            return
        try:
            validate_function_name(function_name, class_name)
            check_if_registered(function_name, class_name)
            do_register(function_name, class_name)
            try_append_registration_log(function_name, class_name, write_to_temporary_logfile)
        except UDFRegistrationException as e:
            self.logger.error(str(e))

    def deregister(self, function_name: str) -> None:
        if not self.registration_info[function_name.upper()].get('is_builtin'):
            try:
                append_deregistration_log(function_name)
                del self.registration_info[function_name.upper()]
            except Exception as e:
                self.logger.error(str(e))

    def reflect(self, expression: 'FunctionExpression') -> UDF:
        function_name = expression.get_function_name().upper()
        if not self.registration_info[function_name]:
            raise QueryProcessException(f"Failed to reflect UDF instance because UDF {function_name} has not been registered.")
        try:
            return UDF(self.registration_info[function_name]['class'], *self.registration_info[function_name].get('args'))
        except Exception as e:
            self.logger.error(str(e))

    def get_registration_information(self) -> list:
        return [UDFRegistrationInformation(**info) for info in self.registration_info.values()]

    @staticmethod
    def getInstance() -> 'UDFRegistrationService':
        if not hasattr(UDFRegistrationService, '_instance'):
            UDFRegistrationService._instance = UDFRegistrationService()
        return UDFRegistrationService._instance

class UDFLogWriter:
    REGISTER_TYPE = 0
    DEREGISTER_TYPE = 1

    def __init__(self, log_file_name: str):
        self.log_file_name = log_file_name
        self.file = open(self.log_file_name, 'w')

    def register(self, function_name: str, class_name: str) -> None:
        with self.log_writer_lock:
            try:
                self.file.write(f"{UDFLogWriter.REGISTER_TYPE},{function_name},{class_name}\n")
            except Exception as e:
                raise UDFRegistrationException(str(e))

    def deregister(self, function_name: str) -> None:
        with self.log_writer_lock:
            try:
                self.file.write(f"{UDFLogWriter.DEREGISTER_TYPE},{function_name}\n")
            except Exception as e:
                raise UDFRegistrationException(str(e))

    def close(self):
        if not self.file.closed:
            self.file.close()

    def delete_log_file(self) -> None:
        try:
            import os
            os.remove(self.log_file_name)
        except Exception as e:
            pass

class QueryProcessException(Exception):
    pass

class UDFRegistrationException(Exception):
    pass

class FunctionExpression:
    pass

class UDF:
    pass

class BuiltinFunction:
    pass

class IoTDBDescriptor:
    @staticmethod
    def getInstance() -> 'IoTDBDescriptor':
        if not hasattr(IoTDBDescriptor, '_instance'):
            IoTDBDescriptor._instance = IoTDBDescriptor()
        return IoTDBDescriptor._instance

class SystemFileFactory:
    @staticmethod
    def getFSFactory() -> 'SystemFileFactory':
        if not hasattr(SystemFileFactory, '_fs_factory'):
            SystemFileFactory._fs_factory = SystemFileFactory()
        return SystemFileFactory._fs_factory

IoTDBDescriptor. getInstance()
