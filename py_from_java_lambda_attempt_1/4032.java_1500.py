Here is the translation of the given Java code into Python:

```Python
class MoveBlockDialog:
    def __init__(self, model, tool):
        self.model = model
        self.tool = tool
        self.changing = False
        super().__init__("Move Memory Block")
        set_help_location(HelpLocation("MEMORY_MAP", "Move Block"))
        self.add_work_panel(self.build_main_panel())
        self.add_ok_button()
        self.add_cancel_button()

    def move_block_completed(self, task):
        cursor.set_default_cursor()
        success = task.was_successful()
        self.set_ok_enabled(success)
        status_text(task.get_status_message())

        Swing.run_later(lambda: 
            if success:
                close()
                model.dispose()
        )

    def state_changed(self):
        self.set_ok_enabled(False)
        self.changing = True
        if not is_visible():
            factory = model.get_address_factory()
            new_start_field.set_address(factory, True, False)
            new_end_field.set_address(factory, True, False)

        new_start = model.get_new_start_address()
        if new_start:
            if new_start != new_start_field.get_address():
                new_start_field.set_address(new_start)

        new_end = model.get_new_end_address()
        if new_end:
            if new_end != new_end_field.get_address():
                new_end_field.set_address(new_end)

        self.changing = False
        message = model.get_message()
        status_text(message)

        if not is_visible():
            block_name_label.setText(model.name)
            orig_start_label.setText(str(model.start_address))
            orig_end_label.setText(str(model.end_address))
            length_label.setText(model.length_string())
            tool.show_dialog(self, tool.component_provider(PluginConstants.MEMORY_MAP))

        elif message == "":
            self.set_ok_enabled(True)

    def ok_callback(self):
        set_ok_enabled(False)
        cursor = Cursor.get_predefined_cursor(Cursor.WAIT_CURSOR)

        task = model.make_task()

        TaskBuilder.with_task(task).set_parent(self.component()).launch_modal()

    def cancel_callback(self):
        close()
        model.dispose()

    def build_main_panel(self):
        panel = JPanel(PairLayout(5, 20, 150))
        panel.setBorder(BorderFactory.create_empty_border(20, 20, 20, 20))

        block_name_label = GDLabel(".text")
        block_name_label.setName("blockName")

        orig_start_label = GDLabel("1001000")
        orig_start_label.setName("origStart")

        orig_end_label = GDLabel("1002000")
        orig_end_label.setName("origEnd")

        length_label = GDLabel("4096 (0x1000)")
        length_label.setName("length")

        new_start_field = AddressInput()
        new_start_field.setName("newStart")

        new_end_field = AddressInput()
        new_end_field.setName("newEnd")

        panel.add(GLabel("Name:", SwingConstants.RIGHT))
        panel.add(block_name_label)
        panel.add(GLabel("Start Address:", SwingConstants.RIGHT))
        panel.add(orig_start_label)
        panel.add(GLabel("End Address:", SwingConstants.RIGHT))
        panel.add(orig_end_label)
        panel.add(GLabel("Length:", SwingConstants.RIGHT))
        panel.add(length_label)
        panel.add(GLabel("New Start Address:", SwingConstants.RIGHT))
        panel.add(new_start_field)
        panel.add(GLabel("New End Address:", SwingConstants.RIGHT))
        panel.add(new_end_field)

        return panel

    def start_changed(self):
        if self.changing:
            return
        new_start = new_start_field.get_address()
        if new_start:
            model.set_new_start_address(new_start)
        else:
            status_text("Invalid Address")
            set_ok_enabled(False)

    def end_changed(self):
        if self.changing:
            return
        new_end = new_end_field.get_address()
        if new_end:
            model.set_new_end_address(new_end)
        else:
            status_text("Invalid Address")
            set_ok_enabled(False)
```

Note: This code is a direct translation of the given Java code into Python. It does not include any error handling or exception checking, which you may want to add depending on your specific requirements.