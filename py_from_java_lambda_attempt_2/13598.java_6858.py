Here is the translation of the Java code into Python:

```Python
class ChooseGhidraInstallationWizardPage:
    def __init__(self):
        super().__init__()
        self.setTitle("Choose a Ghidra Installation")
        self.setDescription("Choose the Ghidra installation to use.")

    def createControl(self, parent):
        container = gtk.Builder()
        container.set_translation_domain(None)
        layout = gtk.GridLayout(3, False)

        ghidra_install_dir_label = gtk.Label(label="Ghidra installation:")
        ghidra_install_dir_combo = gtk.ComboBox(text=ghidra_install_dir_combo)
        ghidra_install_dir_combo.set_layout_data(gtk.GridData(fill_horizontal=True))
        populate_glidra_installation_combo()
        ghidra_install_dir_combo.add_modify_listener(validate)

        add_ghidra_install_dir_button = gtk.Button(label="+")
        add_ghidra_install_dir_button.set_tooltip_text("Adds/manages Ghidra installations.")
        add_ghidra_install_dir_button.connect('clicked', lambda event: self.open_preferences_dialog())

        validate()
        set_control(container)

    def get_glidra_install_dir(self):
        return File(ghidra_install_dir_combo.get_text())

    def validate(self):
        message = None

        if GhidraProjectCreatorPreferences.get_glidra_install_dirs() == []:
            message = "No Ghidra installations found. Click the + button to add one."
        elif ghidra_install_dir_combo.get_text() == "":
            message = "Ghidra installation must be specified."
        else:
            try:
                glidra_install_dir = File(ghidra_install_dir_combo.get_text())
                validate_glidra_installation(glidra_install_dir)
                try:
                    java_config = JavaConfig(glidra_install_dir)
                    if not is_supported_java_home_dir(java_config, java_filter.JDK_ONLY):
                        message = "A supported JDK is not associated with this Ghidra installation. Please run this Ghidra and try again."
                    else:
                        set_error_message(message)
                except (ParseException | IOException) as e:
                    message = f"Failed to determine Ghidra's JDK version. {e.message}"
            except IOException as e:
                message = str(e)

        if message is None:
            page_complete()
        else:
            error_message()

    def populate_glidra_installation_combo(self):
        ghidra_install_dir_combo.remove_all()
        for dir in GhidraProjectCreatorPreferences.get_glidra_install_dirs():
            ghidra_install_dir_combo.add(dir.abspath)
            if dir == GhidraProjectCreatorPreferences.get_glidra_default_install_dir():
                ghidra_install_dir_combo.set_text(dir.abspath)

    def open_preferences_dialog(self):
        dialog = PreferencesUtil.create_preference_dialog(None, GhidraProjectCreatorPreferencePage.class.getName(), None, None)
        dialog.open()
        populate_glidra_installation_combo()
        validate()

class File:
    def __init__(self, path):
        self.path = path

def is_supported_java_home_dir(java_config, java_filter):
    return True
```

Please note that Python does not have direct equivalent of Java's SWT (Standard Widget Toolkit) and Eclipse JFace. So I used `gtk` for GUI operations in the above code.