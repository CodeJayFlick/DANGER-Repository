Here is the translation of the Java code into Python:

```Python
class OpenProgramTask:
    def __init__(self, domain_file_list=None, force_read_only=False):
        self.domain_file_info_list = []
        if domain_file_list:
            for file in domain_file_list:
                self.add_domain_file(file)

    def add_domain_file(self, domain_file, version=-1, force_read_only=False):
        self.domain_file_info_list.append(DomainFileInfo(domain_file, version, force_read_only))

    @property
    def open_programs(self):
        return [program for program in self.program_list]

    @property
    def open_program(self):
        if not self.program_list:
            return None
        return self.program_list[0]

    def run(self):
        task_monitor = TaskMonitor()
        task_monitor.initialize(len(self.domain_file_info_list))
        for domain_file_info in self.domain_file_info_list:
            if task_monitor.is_cancelled():
                break
            self.open_domain_file(domain_file_info)
            task_monitor.increment_progress(1)

    def open_domain_file(self, domain_file_info):
        version = domain_file_info.get_version()
        domain_file = domain_file_info.get_domain_file()

        if version != DomainFile.DEFAULT_VERSION:
            self.open_versioned_file(domain_file, version)
        elif domain_file_info.is_read_only():
            self.open_read_only_file(domain_file, version)
        else:
            self.open_unversioned_file(domain_file)

    def open_read_only_file(self, domain_file, version):
        task_monitor.set_message(f"Opening {domain_file.name}")
        program = domain_file.get_domain_object(version=version, read_only=True)
        if program is not None:
            self.program_list.append(program)

    def open_versioned_file(self, domain_file, version):
        task_monitor.set_message(f"Getting Version {version} for {domain_file.name}")
        program = domain_file.get_domain_object(version=version)
        if program is not None:
            self.program_list.append(program)

    def open_unversioned_file(self, domain_file):
        filename = domain_file.name
        task_monitor.set_message(f"Opening {filename}")

        try:
            program = domain_file.get_domain_object()
            if program is not None:
                self.program_list.append(program)
        except (CancelledException, Exception) as e:
            Msg.show_error("Error Opening File", f"{e}")

    def open_file_maybe_upgrade(self, domain_file):
        recover_file = False
        if not self.silent and domain_file.is_in_writable_project() and domain_file.can_recover():
            recover_file = ask_recover_file(domain_file.name)

        try:
            program = domain_file.get_domain_object(consumer=self.consumer, read_only=False, recover_file=recover_file)
            if program is not None:
                self.program_list.append(program)
        except (VersionException) as e:
            VersionExceptionHandler.show_version_error(None, filename=domain_file.name, content_type=None, action="Open", exception=e)

    def ask_recover_file(self, filename):
        option = OptionDialog.show_yes_no_dialog("Crash Recovery Data Found",
                                                  f"<html>{HTMLUtilities.escape_html(filename)} has crash data.<br>Would you like to recover unsaved changes?")
        return option == OptionDialog.OPTION_ONE

class DomainFileInfo:
    def __init__(self, domain_file, version=-1, force_read_only=False):
        self.domain_file = domain_file
        self.version = version if not domain_file.is_readable() and not domain_file.is_versioned() else domain_file.get_version()
        self.force_read_only = force_read_only

    @property
    def is_read_only(self):
        return self.force_read_only or self.domain_file.is_readable()

    @property
    def get_domain_file(self):
        return self.domain_file

    @property
    def get_version(self):
        return self.version


class TaskMonitor:
    def __init__(self):
        pass

    def initialize(self, count):
        pass

    def is_cancelled(self):
        pass

    def increment_progress(self, step):
        pass

    def set_message(self, message):
        pass
```

Note: This translation assumes that the Java code you provided was part of a larger program. The Python version does not include all the classes and methods from the original Java code, but only those necessary to translate the given code into Python.