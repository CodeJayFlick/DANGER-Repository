class FrontEndTestEnv:
    TEST_PROJECT_NAME = "TestProject"
    PROGRAM_A = "Program_"

    def __init__(self):
        self.env = None
        self.front_end_tool = None
        self.tree = None
        self.root_folder = None
        self.root_node = None

    def setup(self, is_remote=False) -> None:
        if not self.env:
            try:
                self.env = TestEnv()
                self.front_end_tool = self.env.get_front_end_tool()
                self.env.show_front_end_tool()

                if is_remote:
                    start_server()

                self.tree = AbstractGenericTest.find_component(
                    self.front_end_tool.get_tool_frame(), DataTree
                )
                project = self.front_end_tool.get_project()
                root_folder = project.get_project_data().get_root_folder()

                program = build_program(self)
                root_folder.create_file(PROGRAM_A, program, TaskMonitor.DUMMY)
                program.release(self)

                self.root_node = self.tree.get_view_root()
                wait_for_tree()

            except Exception as e:
                print(f"Error setting up environment: {e}")

    def get_root_folder(self) -> DomainFolder:
        return self.root_folder

    def get_tree(self) -> GTree:
        return self.tree

    def get_root_node(self) -> GTreeNode:
        return self.root_node

    # ... other methods ...

def start_server() -> None:
    SharedProjectUtil.delete_test_project(TEST_PROJECT_NAME)
    Preferences.set_property(Preferences.LAST_NEW_PROJECT_DIRECTORY, AbstractGTest.get_test_directory_path())
    try:
        SharedProjectUtil.start_server()
        if not SharedProjectUtil.create_shared_project(front_end_tool, TEST_PROJECT_NAME):
            ServerTestUtil.dispose_server()
            fail("Failed to create shared TestProject in setup")
    except Exception as e:
        SharedProjectUtil.delete_server_root()
        SharedProjectUtil.delete_test_project(TEST_PROJECT_NAME)
        raise e

def build_program(self) -> Program:
    builder = ClassicSampleX86ProgramBuilder("SampleProgram", True, self)
    program_db = builder.get_program()
    return program_db
