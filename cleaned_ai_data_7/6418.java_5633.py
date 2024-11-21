import unittest
from ghidra.app.plugin.core.script import GhidraScriptUtil
from utilities.util.FileUtilities import FileUtilities
from generic.jar.ResourceFile import ResourceFile
from docking.test.AbstractDockingTest import AbstractDockingTest
from ghidra. test.ScriptTaskListener import ScriptTaskListener

class TestGhidraScriptMgrPlugin2(unittest.TestCase):

    def setUp(self):
        pass

    @unittest.skip("Not implemented yet")
    def testRun(self):
        script_name = "HelloWorldScript.java"
        self.select_script(script_name)
        task_flag = GhidraSourceBundle.get_task_listener_flag(script_name)
        TaskUtilities.add_tracked_task_listener(task_flag)

        self.press_run_button()
        self.wait_for_task_end(task_flag)

        console_text = get_console_text()
        self.assertTrue("ConsoleText was \"" + console_text + "\".", console_text.find("> Hello World") >= 0)

    @unittest.skip("Not implemented yet")
    def testScriptWithInnerClassAndLocalClass(self):
        inner_script_file = create_inner_class_script()

        output = run_script_and_get_output(inner_script_file)
        self.assertTrue("Inner class output not found", output.find("I am an inner class") != -1)
        self.assertTrue("External class output not found", output.find("I am an external class") != -1)

    @unittest.skip("Not implemented yet")
    def testScriptRecompileWithAbstractParent_ChangeOnlyParent(self):
        parent_script_file = create_temp_script_file("AbstractParentScript")

        v1_message = "Hello from version 1"
        write_abstract_script_contents(parent_script_file, v1_message)
        child_script_file = create_child_script(parent_script_file, None)

        output = run_script_and_get_output(child_script_file)
        self.assertContainsText(v1_message, output)

        # change the parent script
        v2_message = "Hello from version 2"
        write_abstract_script_contents(parent_script_file, v2_message)
        output = run_script_and_get_output(child_script_file)
        self.assertContainsText(v2_message, output)

    @unittest.skip("Not implemented yet")
    def testScriptsCompileToBinDirectory(self):
        # create a new dummy script
        user_scripts_dir = GhidraScriptUtil.USER_SCRIPTS_DIR
        raw_script_name = self.testName.getMethodName()
        script_filename = raw_script_name + ".java"
        new_script_file = ResourceFile(user_scripts_dir, script_filename)
        if new_script_file.exists():
            self.assertTrue("Unable to delete script file for testing: " + new_script_file,
                new_script_file.delete())

        # remove all class files from the user script dir (none should ever be there)
        class_file_filter = lambda x: x.getName().endswith(".class")
        user_script_dir_files = list(user_scripts_dir.listFiles(class_file_filter))
        for file in user_script_dir_files:
            file.delete()
        self.assertTrue("Unable to delete class files from the user scripts directory",
            len(user_script_dir_files) == 0)

    @unittest.skip("Not implemented yet")
    def testSystemScriptsCompileToDefaultBinDirectory(self):
        # find a system script
        script_name = "HelloWorldScript.java"
        system_script_file = find_script(script_name)

        # compile the system script
        script_id = env.run_script(system_script_file.getFile(False))
        self.wait_for_script_completion(script_id, 20000)

    @unittest.skip("Not implemented yet")
    def testUserDefinedScriptsWillCompileToUserDefinedDirectory(self):
        # create a user-defined directory
        temp_dir = AbstractGTest.get_test_directory_path()
        temp_script_dir = ResourceFile(temp_dir, "TestScriptDir")
        FileUtilities.delete_dir(temp_script_dir)
        temp_script_dir.mkdir()

        script_dir = ResourceFile(temp_script_dir)

    @unittest.skip("Not implemented yet")
    def testRenameWithTreeFilter(self):
        # debug
        logger = LogManager.getLogger(SelectionManager.class)
        Configurator.setLevel(logger.getName(), Level.TRACE)

        self.press_new_button()
        choose_java_provider()

        save_dialog = AbstractDockingTest.waitFor_dialog_component(SaveDialog.class)
        press_button_by_text(save_dialog, "OK")

    @unittest.skip("Not implemented yet")
    def testRenameScriptDoesNotOverwriteExistingScriptOnDiskThatScriptManagerDoesNotYetKnowAbout(self):
        first_script = load_temp_script_into_editor()
        original_contents = read_file_contents(first_script)

        delete_file(first_script)
        self.assertEditorContentsSame(original_contents)
        assertCannotRefresh()

    @unittest.skip("Not implemented yet")
    def testSaveDirtyEditor_No_ChangesOnDisk(self):
        script = load_temp_script_into_editor()

        changed_contents = change_editor_contents()
        press_save_button()
        self.assertFileSaved(script, changed_contents)

    @unittest.skip("Not implemented yet")
    def testSaveDirtyEditor_ChangesOnDisk_OverwiteDiskFile(self):
        script = load_temp_script_into_editor()

        new_contents = change_editor_contents()
        change_file_on_disk(script)
        press_save_button()
        choose_overwrite_file_on_disk()
        self.assertFileSaved(script, new_contents)

    @unittest.skip("Not implemented yet")
    def testSaveDirtyEditor_ChangesOnDisk_DiscardEditorChanges(self):
        script = load_temp_script_into_editor()

        changed_contents = change_editor_contents()
        disk_changes = change_file_on_disk(script)
        press_save_button()
        choose_discard_editor_changes()
        self.assertEditorContentsSame(disk_changes)

    @unittest.skip("Not implemented yet")
    def testSaveDirtyEditor_ChangesOnDisk_Cancel(self):
        script = load_temp_script_into_editor()

        changed_contents = change_editor_contents()
        disk_changes = change_file_on_disk(script)
        press_save_button()
        choose_cancel()
        self.assertEditorContentsSame(changed_contents)

    @unittest.skip("Not implemented yet")
    def testSaveDirtyEditor_ChangesOnDisk_SaveAs(self):
        script = load_temp_script_into_editor()

        changed_contents = change_editor_contents()
        disk_changes = change_file_on_disk(script)
        press_save_button()
        new_file = choose_save_as()
        self.assertFileSaved(new_file, changed_contents)

    @unittest.skip("Not implemented yet")
    def testSaveDirtyEditor_FileOnDiskIsDeleted(self):
        script = load_temp_script_into_editor()

        changed_contents = change_editor_contents()
        delete_file(script)
        press_save_button()
        self.assertFileSaved(script, changed_contents)

    @unittest.skip("Not implemented yet")
    def testSaveAsDoesNotAllowOverwriteExistingFileThatScriptManagerDoesNotYetKnowAbout(self):
        not_yet_known_script = create_temp_script_file()

    @unittest.skip("Not implemented yet")
    def testSaveAsDoesNotAllowUseOfExistingScriptName(self):
        existing_script = load_temp_script_into_editor()
        self.assertCannotPerformSaveAsByName(existing_script.getName())

    @unittest.skip("Not implemented yet")
    def testSaveAsAllowsUseOfDeletedScriptName(self):
        existing_script = create_temp_script_file()

    @unittest.skip("Not implemented yet")
    def testSaveButtonEnablement(self):
        load_temp_script_into_editor()
        self.assertSaveButtonDisabled()

        change_editor_contents()
        self.assertSaveButtonEnabled()

        press_save_button()
        self.assertSaveButtonDisabled()

    @unittest.skip("Not implemented yet")
    def testScriptInstancesAreNotReused(self):
        script = create_instance_field_script()
        output = run_script_and_get_output(script)
        self.assertTrue("*1*" in output)

        output = run_script_and_get_output(script)
        self.assertTrue("The field of the script still has state--the script was not recreated" and "*2*" in output)

    @unittest.skip("Not implemented yet")
    def testStaticVariableSupport(self):
        script = create_static_field_script()
        output = run_script_and_get_output(script)
        self.assertTrue("*1*" in output)

        output = run_script_and_get_output(script)
        self.assertTrue("The field of the script still has state--the script was not recreated" and "*2*" in output)

if __name__ == '__main__':
    unittest.main()
