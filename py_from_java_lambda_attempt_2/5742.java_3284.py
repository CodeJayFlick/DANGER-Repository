Here is the translation of the Java code into Python:

```Python
class ProgramMappingService:
    PROGRAM_METADATA_MD5 = "Executable MD5"
    PROGRAM_SOURCE_FSRL = "FSRL"

    FSRL_TO_PATH_MAP_SIZE = 1000

    fsrl_to_project_path_map = FixedSizeHashMap(FSRL_TO_PATH_MAP_SIZE)

    def __init__(self):
        pass

    @staticmethod
    def clear():
        with lock(fsrl_to_project_path_map):
            fsrl_to_project_path_map.clear()

    @staticmethod
    def is_file_open(fsrl):
        expected_md5 = fsrl.get_md5()
        open_domain_files = find_open_files()
        for domain_file in open_domain_files:
            opened_domain_object = domain_file.get_opened_domain_object()
            if isinstance(opened_domain_object, Program):
                program = opened_domain_object
                property_list = program.get_options(Program.PROGRAM_INFO)
                fsrl_str = property_list.get_string(PROgramMappingService.PROGRAM_SOURCE_FSRL, None)
                md5 = property_list.get_string(
                    ProgramMappingService.PROGRAM_METADATA_MD5, None
                )
                if (expected_md5 is not None and expected_md5 == md5) or fsrl.is_equivalent(fsrl_str):
                    create_association(fsrl, program)
                    return True
        return False

    @staticmethod
    def is_file_imported_into_project(fsrl):
        return ProgramMappingService.is_file_open(fsrl) or get_cached_domain_file_for(fsrl) is not None

    @staticmethod
    def get_cached_domain_file_for(fsrl):
        path = fsrl_to_project_path_map.get(fsrl)
        if path is None and fsrl.get_md5() is not None:
            fsrl = fsrl.with_md5(None)
            path = fsrl_to_project_path_map.get(fsrl)
        if path is None:
            return None
        domain_file = get_project_file(path)
        if domain_file is None:  # The cached path is no longer valid. Remove the stale path from cache.
            with lock(fsrl_to_project_path_map):
                if fsrl_to_project_path_map.get(fsrl) == path:
                    del fsrl_to_project_path_map[fsrl]
        return domain_file

    @staticmethod
    def create_association(fsrl, program):
        with lock(fsrl_to_project_path_map):
            fsrl_to_project_path_map.put(fsrl, program.domain_file.pathname)
            fsrl_to_project_path_map.put(fsrl.with_md5(None), program.domain_file.pathname)

    @staticmethod
    def find_matching_program_open_iff(fsrl, domain_file=None, consumer=None, program_manager=None, open_state=0):
        if domain_file is None:
            domain_file = get_cached_domain_file_for(fsrl)
        if domain_file is not None and program_manager is not None:
            return program_manager.open_program(domain_file, DomainFile.DEFAULT_VERSION, open_state)

    @staticmethod
    def find_matching_open_program(fsrl, consumer=None):
        expected_md5 = fsrl.get_md5()
        for df in get_open_files():
            opened_domain_object = df.get_opened_domain_object(consumer)
            if isinstance(opened_domain_object, Program):
                program = opened_domain_object
                property_list = program.get_options(Program.PROGRAM_INFO)
                fsrl_str = property_list.get_string(
                    ProgramMappingService.PROGRAM_SOURCE_FSRL, None
                )
                md5 = property_list.get_string(
                    ProgramMappingService.PROGRAM_METADATA_MD5, None
                )
                if (expected_md5 is not None and expected_md5 == md5) or fsrl.is_equivalent(fsrl_str):
                    df.add_consumer(consumer)
                    return program

    @staticmethod
    def search_project_for_matching_files(fsrls, monitor=None):
        project = AppInfo.get_active_project()
        if project is None:
            return {}
        results = {}
        for domain_file in ProjectDataUtils.descendant_files(project.data.root_folder):
            metadata = domain_file.metadata
            fsrl = get_fsrl_from_metadata(metadata)
            md5 = get_md5_from_metadata(metadata)
            if fsrl and monitor.is_cancelled():
                break
            with lock(monitor):
                monitor.increment_progress(1)
            if fsrl:
                create_association(fsrl, domain_file, True)
            elif md5 is not None:
                matched_fsrl = fsrls.get(md5)
                if matched_fsrl is not None:
                    results[matched_fsrl] = domain_file
        return results

    @staticmethod
    def get_md5_from_metadata(metadata):
        return metadata.get(ProgramMappingService.PROGRAM_METADATA_MD5)

    @staticmethod
    def get_fsrl_from_metadata(metadata, domain_file=None):
        fsrl_str = metadata.get(ProgramMappingService.PROGRAM_SOURCE_FSRL)
        if fsrl_str is not None:
            try:
                fsrl = FSRL.from_string(fsrl_str)
                return fsrl
            except MalformedURLException as e:
                Msg.warn(
                    ProgramMappingService,
                    f"Domain file {domain_file.pathname} has a bad FSRL: {fsrl_str}",
                )
        return None

    @staticmethod
    def get_project_file(path):
        project = AppInfo.get_active_project()
        if project is not None:
            data = project.data
            if data is not None:
                return data.file(path)
        return None

    @staticmethod
    def find_open_files():
        files = []
        project = AppInfo.get_active_project()
        if project is not None:
            files = project.open_data
        return files


class FixedSizeHashMap(dict):
    def __init__(self, size):
        self.size = size

    def put(self, key, value):
        if len(self) >= self.size:
            raise Exception("Map full")
        super().update({key: value})

    def clear(self):
        super().clear()
```

Note that I've used Python's built-in `dict` to implement the `FixedSizeHashMap`, and also replaced Java's `synchronized` keyword with Python's `lock` mechanism.