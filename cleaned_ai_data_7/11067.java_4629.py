class VersionControlDialog:
    OK = 0
    APPLY_TO_ALL = 1
    CANCEL = 2

    def __init__(self, addToVersionControl):
        self.addToVersionControl = addToVersionControl
        if self.addToVersionControl:
            super().__init__("Add File to Version Control", True)
        else:
            super().__init__("Check In File(s)", True)

        self.add_work_panel(self.build_main_panel())

    def build_main_panel(self):
        inner_panel = JPanel()
        inner_panel.setLayout(BoxLayout(Y_AXIS))

        icon = ImageIcon("images/vcAdd.png" if self.addToVersionControl else "images/vcCheckIn.png")

        description_label = GDLabel(
            f"{'Add comments to describe the file.' if self.addToVersionControl else 'Add comments to describe changes'}",
            SwingConstants.LEFT
        )
        d_panel = JPanel()
        d_panel.setLayout(BorderLayout(10, 0))
        d_panel.add(JPanel(), BorderLayout.WEST)
        d_panel.add(description_label, BorderLayout.CENTER)

        c_panel = JPanel()
        c_panel.setLayout(BorderLayout())
        c_panel.add(GLabel("Comments:", SwingConstants.LEFT), BorderLayout.NORTH)

        comments_text_area = JTextArea(4, 20)
        scroll_pane = JScrollPane(comments_text_area)

        keep_checkbox = GCheckBox("Keep File Checked Out", True)
        k_panel = JPanel()
        k_panel.setLayout(BorderLayout())
        k_panel.add(keep_checkbox, BorderLayout.WEST)

        inner_panel.add(Box.createVerticalStrut(10))
        inner_panel.add(d_panel)
        inner_panel.add(Box.createVerticalStrut(5))
        inner_panel.add(c_panel)
        inner_panel.add(scroll_pane)
        inner_panel.add(Box.createVerticalStrut(5))
        inner_panel.add(k_panel)

        if not self.addToVersionControl:
            create_keep_file_checkbox = GCheckBox("Create \"keep\" file", False)
            kp_panel = JPanel()
            kp_panel.setLayout(BorderLayout())
            kp_panel.add(create_keep_file_checkbox, BorderLayout.WEST)
            inner_panel.add(kp_panel)

        main_panel = JPanel()
        main_panel.setBorder(EmptyBorder(0, 5, 0, 5))
        main_panel.add(inner_panel)
        return main_panel

    def set_current_filename(self, filename):
        description = f"Add comments to describe {filename}." if self.addToVersionControl else f"Add comments to describe changes to {filename}."
        description_label.setText(description)

    @property
    def action_id(self):
        return 0

    def cancel_callback(self):
        self.action_id = VersionControlDialog.CANCEL
        close()

    def ok_callback(self):
        self.action_id = VersionControlDialog.OK
        close()

    def show_dialog(self, parent):
        tool.show_dialog(self, parent)
        return self.action_id

    @property
    def keep_checked_out(self):
        return keep_checkbox.isSelected()

    @keep_checked_out.setter
    def set_keep_checked_out(self, selected):
        keep_checkbox.setSelected(selected)

    @property
    def should_create_keep_file(self):
        if not self.addToVersionControl:
            return False
        return create_keep_file_checkbox.isSelected()

    @should_create_keep_file.setter
    def set_create_keep_file(self, selected):
        if not self.addToVersionControl:
            create_keep_file_checkbox.setSelected(selected)

    def get_comments(self):
        return comments_text_area.get_text()
