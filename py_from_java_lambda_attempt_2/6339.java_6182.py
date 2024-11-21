Here is the translation of the given Java code into equivalent Python:

```Python
import os
from tempfile import mkdtemp
import time

class DataTypeTestUtils:
    ARCHIVE_FILE_EXTENSION = '.gdt'
    temp_archive_dir = None
    archive_tree = None

    def __init__(self):
        pass  # utils class, no initialization needed in this case

    @staticmethod
    def get_temp_dir():
        if not DataTypeTestUtils.temp_archive_dir:
            DataTypeTestUtils.temp_archive_dir = mkdtemp()
        return DataTypeTestUtils.temp_archive_dir

    @staticmethod
    def create_local_archive_from_existing_archive(filename, existing_filename):
        temp_dir = DataTypeTestUtils.get_temp_dir()
        scratch_file = os.path.join(temp_dir, filename)
        if os.path.exists(scratch_file):
            os.remove(scratch_file)

        packed_db_file = AbstractGenericTest().get_test_data_file(existing_filename)
        if not packed_db_file:
            print(f"No packed DB file named {existing_filename}")
            return None

        temp_db_file = os.path.join(temp_dir, f"copy.{os.path.basename(existing_filename)}")
        FileUtilities.copy_file(packed_db_file, temp_db_file, False)

        fm = FileDataTypeManager().open_file_archive(temp_db_file, True)
        fm.save_as(scratch_file)
        fm.close()

        print(f"Created test archive: {scratch_file}")
        return scratch_file

    @staticmethod
    def open_archive(archive_dir_path, archive_name, checkout, plugin):
        file = os.path.join(archive_dir_path, archive_name)
        dataTypeManagerHandler = plugin.get_data_type_manager_handler()
        dataTypeManagerHandler.open_archive(file, checkout, False)

        while True:
            if not (plugin.get_provider().get_g_tree()).is_busy():
                break
            time.sleep(0.05)  # wait for the tree to rebuild

        return (ArchiveNode)(plugin.get_provider().get_g_tree()).view_root().child(os.path.basename(archive_name))

    @staticmethod
    def close_archive(archive_node, delete_file):
        if archive_node:
            try:
                do_close_archive(archive_node, delete_file)
            except Exception as e:
                raise RuntimeError(f"Exception closing archive on Swing thread!: {e}")

    @staticmethod
    def check_out_archive(archive_name, plugin):
        archive_node_name = os.path.basename(archive_name)
        tree = plugin.get_provider().get_g_tree()
        root = tree.model_root

        if not (ArchiveNode)(root).child(archive_node_name):
            raise ValueError(f"Unable to locate an archive by the name: {archive_node_name}")

        ArchiveUtils.lock_archive((FileArchive)(archive_node.get_archive()))

    @staticmethod
    def trim_full_archive_name(archive_name):
        if archive_name.endswith(DataTypeTestUtils.ARCHIVE_FILE_EXTENSION):
            return archive_name[: -len(DataTypeTestUtils.ARCHIVE_FILE_EXTENSION)]
        else:
            return archive_name

    @staticmethod
    def create_open_and_checkout_archive(archive_name, plugin):
        DataTypeTestUtils.create_archive(archive_name)
        return DataTypeTestUtils.open_archive(archive_name, True, plugin)

    @staticmethod
    def copy_open_and_checkout_archive(archive_name, plugin):
        DataTypeTestUtils.copy_archive(archive_name)
        return DataTypeTestUtils.open_archive(archive_name, True, plugin)

    @staticmethod
    def perform_action(action, program, tree):
        AbstractGenericTest().run_swings(lambda: action.action_performed(None))
```

Please note that this is a direct translation of the given Java code into equivalent Python. The actual functionality and usage may vary depending on your specific requirements.