import os
from threading import Thread
from time import sleep
from tkinter.filedialog import askdirectory
from tkinter.messagebox import showinfo

class BundleStatusManagerTest:
    BUNDLE_PATH = "$GHIDRA_HOME/Features/Base/ghidra_scripts"
    SCRIPT_NAME = "HelloWorldScript.java"
    SCRIPT_PATH = os.path.join(BUNDLE_PATH, SCRIPT_NAME)

    def __init__(self):
        self.bundle_status_provider = None
        self.bundle_status_table = None
        self.bundle_status_model_table = None

        self.test_bundle_host_listener = TestBundleHostListener()

    @classmethod
    def translate_seperators(cls, path):
        if os.path.sep != "/":
            return path.replace("/", os.path.sep)
        return path

    def setup_bundle_status_tests(self):
        bundle_status_action = get_action("Script Directories")
        perform_action(bundle_status_action, False)
        wait_for_swing()
        self.bundle_status_provider = get_component_provider()
        self.bundle_status_table = get_instance_field("bundle_status_table", self.bundle_status_provider)
        self.bundle_status_model_table = get_instance_field("bundle_status_model_table", self.bundle_status_provider)

    def cleanup_bundle_status_tests(self):
        provider.get_bundle_host().remove_listener(self.test_bundle_host_listener)

    @classmethod
    def test_disable_enable_script_directory(cls, bundle_path):
        view_row = cls.get_bundle_row(bundle_path)
        select_row(view_row)

        status = cls.bundle_status_model_table.get_row_object(view_row)

        assert status.is_enabled()
        script_file = os.path.join(SCRIPT_PATH)
        assert os.path.exists(script_file)

        disable_via_gui(view_row)
        assert not status.is_enabled()
        assert not os.path.exists(script_file)

        enable_via_gui(view_row)
        assert status.is_enabled()
        assert os.path.exists(script_file)

    @classmethod
    def test_run_clean_run(cls):
        view_row = cls.get_bundle_row(SCRIPT_PATH)
        select_rows([view_row])

        status = cls.bundle_status_model_table.get_row_object(view_row)

        assert status.is_enabled()
        script_file = os.path.join(SCRIPT_PATH)
        assert os.path.exists(script_file)

        select_and_run_script(SCRIPT_NAME)

        clean_via_gui(view_row)
        run_selected_script(SCRIPT_NAME)

    @classmethod
    def test_add_run_clean_remove_two_bundles(cls):
        expected_output = "Hello from pack2.Klass2\n"
        dir1 = get_test_directory_path() + "/test_scripts1"
        dir2 = get_test_directory_path() + "/test_scripts2"

        try:
            os.makedirs(dir1)
            os.makedirs(dir2)

            script_file = open(os.path.join(dir1, "HelloWorldScript.java"), 'w')
            script_file.write("import pack1.Klass1;\n" +
                              "public class HelloWorldScript extends GhidraScript {\n" +
                              "   @Override\n" +
                              "  protected void run() throws Exception {\n" +
                              "    new Klass1(this).hello();\n" +
                              "   }\n" +
                              "}\n")
            script_file.close()

            pack1 = os.path.join(dir1, "pack1")
            os.makedirs(pack1)
            file = open(os.path.join(pack1, "Klass1.java"), 'w')
            file.write("package pack1;\n" +
                       "import ghidra.app.script.GhidraScript;\n" +
                       "public class Klass1 {\n" +
                       "  GhidraScript script;\n" +
                       "  public Klass1(GhidraScript script) {\n" +
                       "    this.script = script;\n" +
                       "   }\n" +
                       "\n" +
                       "  public void hello() {\n" +
                       "    new Klass2(script).hello();\n" +
                       "   }\n" +
                       "}\n")
            file.close()

            pack2 = os.path.join(dir2, "pack2")
            os.makedirs(pack2)
            file = open(os.path.join(pack2, "Klass2.java"), 'w')
            file.write("package pack2;\n" +
                       "import ghidra.app.script.GhidraScript;\n" +
                       "public class Klass2 {\n" +
                       "  GhidraScript script;\n" +
                       "  public Klass2(GhidraScript script) {\n" +
                       "    this.script = script;\n" +
                       "   }\n" +
                       "\n" +
                       "  public void hello() {\n" +
                       "    script.println(\"Hello from pack2.Klass2\");\n" +
                       "   }\n" +
                       "}\n")
            file.close()

            add_bundles_via_gui(dir1, dir2)

            output = select_and_run_script(SCRIPT_NAME)
            assert expected_output in output

            row1 = get_bundle_row(dir1)
            row2 = get_bundle_row(dir2)
            assert not os.path.exists(os.path.join(BUNDLE_PATH))

        finally:
            for file in [os.path.join(dir1, "HelloWorldScript.java"), os.path.join(pack1, "Klass1.java"),
                         os.path.join(pack2, "Klass2.java")]:
                if os.path.exists(file):
                    os.remove(file)

    @classmethod
    def get_bundle_row(cls, bundle_path):
        return askdirectory()

    @classmethod
    def add_bundles_via_gui(cls, *bundle_files):
        action = get_action("AddBundles")
        perform_action(action)
        wait_for_swing()
        chooser = get_instance_field("chooser", None)

        for file in bundle_files:
            os.chdir(file)
            files = askdirectory()

        run_swing(lambda: chooser.set_current_directory(files))
        wait_for_update_on_chooser(chooser)

    @classmethod
    def select_and_run_script(cls, script_name):
        env.get_tool().show_component_provider(provider, True)
        select_script(script_name)
        output = run_selected_script(script_name)
        env.get_tool().show_component_provider(bundle_status_provider, True)
        return output

class TestBundleHostListener:
    activation_latch = None
    disablement_latch = None

    def __init__(self):
        self.reset()

    def reset(self):
        self.activation_latch = CountDownLatch(1)
        self.disablement_latch = CountDownLatch(1)

    @classmethod
    def await_activation(cls, timeout=5000):
        cls.activation_latch.await(timeout)

    @classmethod
    def await_disablement(cls, timeout=5000):
        cls.disablement_latch.await(timeout)


if __name__ == "__main__":
    pass

