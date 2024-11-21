Here is the translation of the given Java code into Python:

```Python
import io
from abc import ABCMeta, abstractmethod


class GhidraVersionTrackingScript:
    def __init__(self):
        self.vt_session = None
        self.source_program = None
        self.destination_program = None
        self.transaction_id = 0

    def create_version_tracking_session(self, source_program_path: str, destination_program_path: str) -> None:
        if self.vt_session is not None:
            raise RuntimeError("Attempted to open a new session with one already open!")

        self.source_program = self.open_program(source_program_path)
        self.destination_program = self.open_program(destination_program_path)

        self.create_version_tracking_session("New Session", self.source_program, self.destination_program)

    def create_version_tracking_session(self, name: str, source: 'Program', destination: 'Program') -> None:
        if self.vt_session is not None:
            raise RuntimeError("Attempted to create a new session with one already open!")

        self.source_program = source
        self.destination_program = destination

        if not self.source_program.is_used_by(self):
            self.source_program.add_consumer(self)

        if not self.destination_program.is_used_by(self):
            self.destination_program.add_consumer(self)

        self.vt_session = VTSessionDB.create_vt_session(name, self.source_program, self.destination_program, self)
        self.transaction_id = self.vt_session.start_transaction("VT Script")

    def open_version_tracking_session(self, path: str) -> None:
        if self.vt_session is not None:
            raise RuntimeError("Attempted to open a session with one already open!")

        project_data = state.get_project().get_project_data()
        file = project_data.get_file(path)
        self.vt_session = VTSessionDB(file.get_domain_object(self, True, True))
        self.source_program = self.vt_session.get_source_program()
        self.destination_program = self.vt_session.get_destination_program()

        if not self.source_program.is_used_by(self):
            self.source_program.add_consumer(self)

        if not self.destination_program.is_used_by(self):
            self.destination_program.add_consumer(self)

        self.transaction_id = self.vt_session.start_transaction("VT Script")

    def save_version_tracking_session(self) -> None:
        self.vt_session.end_transaction(self.transaction_id, True)
        self.vt_session.save()
        self.transaction_id = self.vt_session.start_transaction("VT Script")

    def save_session_as(self, path: str, name: str) -> None:
        folder = state.get_project().get_project_data().get_folder(path)
        file = folder.create_file(name, self.vt_session)
        self.vt_session.set_name(name)

    @abstractmethod
    def cleanup(self, success: bool) -> None:
        pass

    def close_version_tracking_session(self):
        if self.vt_session is not None:
            self.vt_session.end_transaction(self.transaction_id, True)
            self.vt_session.release(self)

    def open_program(self, path: str) -> 'Program':
        project_data = state.get_project().get_project_data()
        file = project_data.get_file(path)
        return Program(file.get_domain_object(self, True, True))

    @abstractmethod
    def close_program(self, program: 'Program') -> None:
        pass

    def get_source_functions(self) -> set[str]:
        if self.vt_session is not None:
            return {function.name for function in self.vt_session.get_source_program().get_function_manager().get_functions(True)}
        else:
            raise RuntimeError("You must have an open vt session")

    def get_destination_functions(self) -> set[str]:
        if self.vt_session is not None:
            return {function.name for function in self.vt_session.get_destination_program().get_function_manager().get_functions(True)}
        else:
            raise RuntimeError("You must have an open vt session")

    def run_correlator(self, name: str) -> None:
        if self.vt_session is not None:
            correlator_factory = get_correlator_factory(name)
            correlator = correlator_factory.create_correlator(None, self.source_program,
                                                                 self.source_program.get_memory().get_loaded_and_initialized_address_set(),
                                                                 self.destination_program,
                                                                 self.destination_program.get_memory().get_loaded_and_initialized_address_set(), VTOptions("dummy"))
            correlator.correlate(self.vt_session)
        else:
            raise RuntimeError("You must have an open vt session to run a correlator")

    def get_matches_from_last_run_correlator(self) -> list['VTMatch']:
        match_sets = self.vt_session.get_match_sets()
        last_set = match_sets[-1]
        return last_set.get_matches()

    def get_source_function(self, match: 'VTMatch') -> 'Function':
        association = match.association
        source_program = self.vt_session.get_source_program()
        function_manager = source_program.get_function_manager()
        return function_manager.get_function_at(association.source_address)

    def get_destination_function(self, match: 'VTMatch') -> 'Function':
        association = match.association
        destination_program = self.vt_session.get_destination_program()
        function_manager = destination_program.get_function_manager()
        return function_manager.get_function_at(association.destination_address)


class Program:
    pass


def main():
    script = GhidraVersionTrackingScript()


if __name__ == "__main__":
    main()

```

Please note that this is a direct translation of the given Java code into Python. It may not be perfect, as there are some differences between the two languages.