class LoadPdbTask:
    def __init__(self, program: 'Program', pdb_file: str, use_ms_dia_parser: bool, control: dict, service: object):
        self.program = program
        self.pdb_file = pdb_file
        self.use_ms_dia_parser = use_ms_dia_parser
        self.control = control
        self.service = service

    def run(self) -> None:
        wrapped_monitor = WrappingTaskMonitor()
        log = MessageLog()

        if self.use_ms_dia_parser:
            try:
                parser = PdbParser(self.pdb_file, self.program, self.service)
                parser.parse(wrapped_monitor)
                parser.open_data_type_archives(wrapped_monitor)
                parser.apply_to(log)
            except (PdbException, DuplicateIdException) as e:
                log.append_msg(f"PDB Error: {e.message}")
        else:
            try:
                pdb_reader_options = PdbReaderOptions()
                pdb_applicator_options = PdbApplicatorOptions()

                pdb_applicator_options.set_processing_control(self.control)

                with AbstractPdb.parse(self.pdb_file, pdb_reader_options) as pdb:
                    wrapped_monitor.set_message(f"PDB: Parsing {self.pdb_file}...")
                    pdb.deserialize(wrapped_monitor)
                    applicator = PdbApplicator(self.pdb_file, pdb)
                    applicator.apply_to(self.program, self.service, self.program.get_image_base(), pdb_applicator_options, wrapped_monitor, log)

            except (PdbException) as e:
                log.append_msg(f"PDB Error: {e.message}")

        if log.has_messages():
            result_messages = log.to_string()
        else:
            result_messages = ""

    @property
    def result_messages(self):
        return self.result_messages

    @result_messages.setter
    def result_messages(self, value):
        self._result_messages = value

    @property
    def result_exception(self):
        return self._result_exception

    @result_exception.setter
    def result_exception(self, value):
        self._result_exception = value


class WrappingTaskMonitor:
    pass  # This class is not implemented in the original Java code. It seems to be a wrapper around TaskMonitor.


class MessageLog:
    pass  # This class is not implemented in the original Java code. It seems to be used for logging messages.


class PdbParser:
    def __init__(self, pdb_file: str, program: 'Program', service: object):
        self.pdb_file = pdb_file
        self.program = program
        self.service = service

    def parse(self) -> None:
        pass  # This method is not implemented in the original Java code.

    def open_data_type_archives(self) -> None:
        pass  # This method is not implemented in the original Java code.


class PdbReaderOptions:
    pass


class PdbApplicatorControl(dict):
    pass


class Program:
    @property
    def get_image_base(self):
        return self._get_image_base

    @get_image_base.setter
    def _get_image_base(self, value):
        self._get_image_base = value


# The following classes are not implemented in the original Java code. They seem to be used for parsing and applying PDB files.
class AbstractPdb:
    pass  # This class is abstract.


class PdbApplicatorOptions(dict):
    pass
