import os
from tkinter import filedialog, messagebox

class CreateHelpTemplateScript:
    def run(self):
        tool = state.get_tool()
        plugins = self.get_sorted_plugins(tool)
        selected_plugin = filedialog.askdirectory(title="Select Plugin To Use To Generate Help", initialdir=plugins[0])
        if not selected_plugin:
            print("no plugin selected, no help template created.")
            return
        output_directory = filedialog.askdirectory(title="Select Directory To Write Help File")
        if not output_directory:
            print("no output directory selected, no help template created.")
            return
        output_file = os.path.join(output_directory, selected_plugin + ".html")
        if os.path.exists(output_file):
            keep_existing = messagebox.askyesno("Help File Already Exists", "The help file for {} already exists.\nDo you want to keep the existing file?".format(selected_plugin))
            if not keep_existing:
                return
        self.write_help_file(tool, selected_plugin, output_file)

    def write_help_file(self, tool, plugin, output_file):
        with open(output_file, 'w') as f:
            try:
                f.write("""
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<title>{}</title>
<link rel="stylesheet" type="text/css" href="../../shared/Frontpage.css">
</head>
<body>
<h1>{}</h1>
<h2>Introduction</h2>
<blockquote>

</blockquote>
<h2>Actions</h2>
<blockquote>
{}
</blockquote>
</body>
</html>
""".format(plugin, plugin))
                actions = self.get_actions(tool, plugin)
                for action in actions:
                    f.write("<h3><A name=\"{}\"></A>{}</h3>\n".format(action.replace(' ', '_'), action) + "<blockquote>\n")
            finally:
                f.close()

    def get_actions(self, tool, plugin):
        return sorted(KeyBindingUtils.getKeyBindingActionsForOwner(tool, plugin), key=lambda x: x.name)

    def get_sorted_plugins(self, tool):
        return sorted(tool.getManagedPlugins(), key=lambda x: x.getName())

# Usage
script = CreateHelpTemplateScript()
state = ...  # This should be replaced with the actual state object.
script.run()
