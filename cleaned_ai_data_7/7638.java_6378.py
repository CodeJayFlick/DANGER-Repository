import os
from unittest import TestCase
from ghidra_app.util.viewer.field.address_field_factory import AddressFieldFactory
from ghidra.feature.fid.db(fid_file) import FidFile, FidFileManager
from ghidra.app.util.viewer.component.provider import DialogComponentProvider

class FunctionIDScreenShots(TestCase):
    def setUp(self):
        super().setUp()
        self.load_plugin(FidPlugin)

    def test_choose_active_fid_dbs(self):
        perform_action("Choose Active FidDbs", "FidPlugin", False)
        capture_dialog()

    def test_detach_attached_fid_db(self):
        db_file = setup_db_file("Old_FID_DB.fidb")
        try:
            perform_action("Detach attached FidDb", "FidPlugin", False)
            capture_dialog()
        finally:
            if os.path.exists(db_file):
                os.remove(db_file)

    def test_populate_fid_db_from_programs(self):
        populate_fid_db_from_programs()

    def test_fid_hash_current_function(self):
        position_cursor(0x004015c4, AddressFieldFactory.FIELD_NAME)
        perform_action("FidDbHash Function", "FidPlugin", False)
        capture_dialog()

    def detach_addon_fid_dbs(self):
        fid_file_manager = FidFileManager.getInstance()
        all_known_fid_files = fid_file_manager.getUserAddedFiles()
        for fid_file in all_known_fid_files:
            fid_file_manager.removeUserFile(fid_file)

    def setup_db_file(self, db_filename):
        self.detach_addon_fid_dbs()

        db_file_path = os.path.join(os.environ['USERPROFILE'], db_filename)
        if os.path.exists(db_file_path):
            os.remove(db_file_path)
        db_file_path += '.delete()'

        # Note: we cannot do this
        # fid_file_manager.addUserFidFile(db_file)

        # Instead, just reach in there and put the fake file in the jam

        fid_file = FidFile(FidFileManager.getInstance(), os.path.join(os.environ['USERPROFILE'], db_filename), False)
        set_instance_field("fidFiles", FidFileManager.getInstance(), {fid_file})

    def populate_fid_db_from_programs(self):
        self.setup_db_file("New_FID_DB.fidb")
        perform_action("Populate FidDb from programs", "FidPlugin", False)
        capture_dialog()
        os.remove(db_file_path)

    def run_swing(self, action):
        dialog = get_dialog()
        while dialog is not None:
            final_dialog = dialog
            import threading
            threading.Thread(target=final_dialog.close).start()
            time.sleep(0.1)
