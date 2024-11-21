Here is the translation of the Java code into equivalent Python code:

```Python
import os
import time
from threading import sleep

class SharedProjectUtil:
    SERVER_PORT = 12345
    LOCALHOST = '127.0.0.1'
    USER = 'username'

    def __init__(self):
        self.server_root = None
        self.repository_server = None

    @staticmethod
    def create_localhost_string():
        try:
            return socket.gethostname()
        except UnknownHostException as e:
            return SharedProjectUtil.LOCALHOST

    @classmethod
    def create_shared_project(cls, front_end_tool, project_name):
        print(f"SharedProjectUtil.create_shared_project(): {project_name}")

        util_project_listener = UtilProjectListener(front_end_tool)
        front_end_tool.add_project_listener(util_project_listener)

        action = cls.get_action(front_end_tool, "New Project")
        AbstractDockingTest.perform_action(action, False)
        time.sleep(1)  # wait for swing to finish

        wizard_manager = AbstractDockingTest.wait_for_dialog_component(WizardManager)
        project_type_panel = AbstractDockingTest.find_component(wizard_manager, ProjectTypePanel)

        rb = AbstractGenericTest.find_abstract_button_by_text(project_type_panel, "Shared Project")
        SwingUtilities.invokeLater(lambda: rb.setSelected(True))

        next_button = AbstractDockingTest.find_button_by_text(wizard_manager, "Next >>")
        finish_button = AbstractDockingTest.find_button_by_text(wizard_manager, "Finish")

        AbstractGenericTest.press_button(next_button)
        time.sleep(1)  # wait for swing to finish

        server_info_panel = AbstractDockingTest.find_component(wizard_manager, ServerInfoPanel)

        server_field = AbstractGenericTest.find_component(server_info_panel, JTextField)
        port_number_field = AbstractGenericTest.find_component(server_info_panel, JTextField)

        SwingUtilities.invokeLater(lambda: [server_field.setText(SharedProjectUtil.LOCALHOST), port_number_field.setText(str(cls.SERVER_PORT))])
        time.sleep(1)  # wait for swing to finish

        AbstractGenericTest.press_button(next_button)
        time.sleep(1)  # wait for swing to finish

        repository_panel = AbstractDockingTest.find_component(wizard_manager, RepositoryPanel)

        rep_list = AbstractGenericTest.find_component(repository_panel, JList)
        SwingUtilities.invokeLater(lambda: rep_list.setSelectedIndex(0))
        time.sleep(1)  # wait for swing to finish

        select_project_panel = AbstractDocker
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments based on your specific use case.

Here are some key differences between the two languages:

- In Python, we don't need to specify types for variables or method parameters.
- We can directly access attributes using dot notation (e.g., `obj.attribute`).
- The equivalent of Java's `System.out.println()` is simply `print()`.
- There is no direct equivalent of Java's `SwingUtilities.invokeLater()` in Python. Instead, we use the `threading` module and its `sleep()` function to simulate a delay.
- We don't need to specify exception types when declaring methods or variables.

This code should be run with Python 3.x as it uses some features that are not available in earlier versions of Python (like f-string formatting).