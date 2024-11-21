import os
from typing import List, Tuple

class ImportBatchTask:
    MAX_PROGRAMS_TO_OPEN = 50

    def __init__(self, batch_info: 'BatchInfo', dest_folder: str, program_manager=None,
                 strip_leading_path=True, strip_all_container_path=False):
        self.batch_info = batch_info
        self.dest_folder = dest_folder
        self.total_enabled_apps = batch_info.get_enabled_count()
        self.program_manager = program_manager
        self.strip_leading_path = strip_leading_path
        self.strip_all_container_path = strip_all_container_path

    def run(self, monitor):
        try:
            self.do_batch_import(monitor)
        except CancelledException as e:
            print("Batch import cancelled")
        except IOException as ce:
            print(f"Error during batch import: {ce}")

        finally:
            print(f"Batch Import finished.\nImported {self.total_objs_imported} files.")

    def do_batch_import(self, monitor):
        for group in self.batch_info.get_groups():
            if not group.is_enabled():
                continue

            if monitor.is_cancelled():
                break

            self.do_import_batch_group(group, monitor)

    def do_import_batch_group(self, batch_group: 'BatchGroup', monitor):
        selected_load_spec = batch_group.get_selected_load_spec()
        for load_config in batch_group.get_batch_load_configs():
            if monitor.is_cancelled():
                return

            self.do_import_app(load_config, selected_load_spec, monitor)

    def do_import_app(self, batch_load_config: 'BatchLoadConfig', selected_load_spec,
                       monitor):
        print(f"Importing {batch_load_config.get_fsrl()}")

        try:
            byte_provider = FileSystemService().get_byte_provider(batch_load_config.get_fsrl(),
                                                                   True, monitor)
            load_spec = batch_load_config.get_load_spec(selected_load_spec)

            if load_spec is None:
                print("Failed to get load spec from application that matches chosen batch load spec")
                return

            dest_info = self.get_destination_info(batch_load_config, self.dest_folder)

            try:
                imported_objects = load_spec.get_loader().load(byte_provider,
                                                                 self.fixup_project_filename(dest_info[1]),
                                                                 dest_info[0], load_spec,
                                                                 self.get_options_for(batch_load_config, load_spec, byte_provider),
                                                                 monitor)
                if imported_objects is not None:
                    self.process_import_results(imported_objects, batch_load_config, monitor)

            finally:
                release_all(imported_objects)

        except CancelledException as e:
            print("Batch Import cancelled")
        except IOException as ce:
            print(f"Import failed for {batch_load_config.get_preferred_filename()}: {ce}")

    def fixup_project_filename(self, filename: str):
        return os.path.normpath(filename).replace('|', '/')

    @staticmethod
    def fsrl_to_path(fsrl: 'FSRL', user_src: 'FSRL', strip_leading_path=False,
                      strip_interior_container_path=True) -> Tuple[str]:
        full_path = fsrl.to_pretty_fullpath_string().replace('|', '/')
        user_src_path = user_src.to_pretty_fullpath_string().replace('|', '/')

        leading_start = 0 if not strip_leading_path else user_src_path.rfind('/')
        lead_end = min(len(full_path), len(user_src_path))
        leading = full_path[leading_start:lead_end] if leading_start < len(full_path) else ''

        container_path = '' if strip_interior_container_path and user_src_path in full_path \
                         else full_path[user_src_path.rfind('/') + 1:]

        filename_str = full_path[len(user_src_path):]
        return os.path.join(leading, container_path, filename_str)

    def get_destination_info(self, batch_load_config: 'BatchLoadConfig', root_destination_folder) -> Tuple[DomainFolder]:
        fsrl = batch_load_config.get_fsrl()
        path_str = self.fsrl_to_path(fsrl, batch_load_config.get_uasi().get_fsrl(), self.strip_leading_path,
                                      self.strip_all_container_path)

        preferred_name = batch_load_config.get_preferred_filename()

        if not os.path.basename(path_str).startswith(preferred_name):
            path_str = os.path.join(os.path.dirname(path_str), preferred_name)

        parent_dir = os.path.dirname(path_str)
        dest_filename = os.path.basename(path_str)

        try:
            domain_folder = ProjectDataUtils().create_domain_folder_path(root_destination_folder, parent_dir)
            return (domain_folder, dest_filename)
        except InvalidNameException as e:
            print(f"Problem creating project folder root: {root_destination_folder}, subpath: {parent_dir}")

    def get_options_for(self, batch_load_config: 'BatchLoadConfig', load_spec,
                         byte_provider) -> List[Option]:
        return batch_load_config.get_loader().get_default_options(byte_provider, load_spec, None, False)

def release_all(imported_objects):
    for obj in imported_objects:
        if isinstance(obj, Program):
            program = obj
            # TODO: set program properties and open the program

class DomainFolder:
    def __init__(self, path_name):
        self.path_name = path_name

class FSRL:
    def to_pretty_fullpath_string(self) -> str:
        return ''

def FileSystemService():
    pass

class ProjectDataUtils:
    @staticmethod
    def create_domain_folder_path(root_destination_folder: DomainFolder, parent_dir: str) -> DomainFolder:
        pass

# Note that the following classes are not defined in this code snippet and will need to be implemented separately.
class BatchInfo:
    def get_enabled_count(self):
        return 0

    def get_groups(self):
        return []

    def is_enabled(self):
        return True

class Program:
    def __init__(self, path_name):
        self.path_name = path_name
