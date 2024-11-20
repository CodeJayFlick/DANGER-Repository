import os
from tempfile import TemporaryDirectory

class ProgramUserDataTest:
    def setUp(self):
        with TemporaryDirectory() as temp_dir:
            self.project_locator = f"{temp_dir}/test"
            project_test_utils.delete_project(temp_dir, "Test")
            project_manager = TestProjectManager()
            project = project_manager.create_project(self.project_locator, None, True)
            data_dir = os.path.join(project_locator, ProjectFileManager.INDEXED_DATA_FOLDER_NAME)
            user_dir = os.path.join(project_locator, ProjectFileManager.USER_FOLDER_NAME)

    def tearDown(self):
        if self.project:
            self.project.close()
        project_test_utils.delete_project(temp_dir, "Test")

    def change(self, program_p, property_name="STRING", address=0, value="Str0"):
        tx_id = program_p.start_transaction("change")
        try:
            program_p.set_executable_path(str(rand.randint(1, 100)))
        finally:
            program_p.end_transaction(tx_id)

    def get_latest_db_version(self, db_dir):
        ver = -1
        for f in os.listdir(db_dir):
            if f.startswith("db.") and f.endswith(".gbf"):
                str_val = f[3:-4]
                val = int(str_val)
                if val > ver:
                    ver = val
        return ver

    @staticmethod
    def test_save_as():
        # User data should not exist following import/upgrade
        assert os.path.isdir(user_dir)

        userDataSubDir = os.path.join(user_dir, "00")
        assert not os.path.isdir(userDataSubDir)

        program_p = df.get_domain_object(self, False, False)
        space = program_p.get_address_factory().get_default_address_space()
        try:
            # Modify program content - no user data should be saved
            change(program_p)
            assert program_p.is_changed()
            program_p.save("save", TaskMonitor.DUMMY)
            assert not program_p.is_changed()
            assert not os.path.isdir(userDataSubDir)

            ver = get_latest_db_version(db_dir)

        finally:
            program_p.release(self)

    @staticmethod
    def test_lazy_save_and_delete():
        # NOTE: test has been written to work with IndexedLocalFileSystem storage schema

        # User data should not exist following import/upgrade
        assert os.path.isdir(user_dir)

        userDataSubDir = os.path.join(user_dir, "00")
        assert not os.path.isdir(userDataSubDir)

        db_dir = os.path.join(data_dir, "00/~00000000.0.db")

    @staticmethod
    def test_project_open_reconcile():
        # TODO: Multi-user repository connect case not tested

        program_p = df.get_domain_object(self, False, False)
        space = program_p.get_address_factory().get_default_address_space()
        try:
            # Create user data content
            change(program_p)

        finally:
            program_p.release(self)

    def invoke_instance_method(self, method_name):
        return getattr(project_data, method_name)()

if __name__ == "__main__":
    unittest.main()
