import os
from threading import Thread
class CParserTask:
    def __init__(self, plugin, filenames, options, data_file_name):
        self.plugin = plugin
        self.filenames = filenames
        self.options = options
        self.data_file_name = data_file_name

    def run(self):
        try:
            if not os.path.exists(data_file_name):
                dt_mgr = FileDataTypeManager.createFileArchive(data_file_name)
            else:
                dt_mgr = FileDataTypeManager.loadFileArchive(data_file_name)

            plugin.parse(filenames, options, dt_mgr)

            if data_file_name and dt_mgr.get_data_type_count():
                try:
                    dt_mgr.save()
                    dt_mgr.close()

                    def show_info_message(plugin):
                        Msg.show_info(
                            CParserTask.__class__,
                            plugin.get_dialog().get_component(),
                            "Created Archive File",
                            f"Successfully created archive file {dt_mgr.get_filename()}"
                        )

                    Thread(target=show_info_message, args=(plugin)).start()
                except DuplicateFileException as e:
                    Msg.show_error(self, plugin.get_dialog().get_component(), "Error During Save", str(e))
                except Exception as e:
                    Msg.show_error(
                        self,
                        plugin.get_dialog().get_component(),
                        "Error During Save",
                        f"Could not save to file {data_file_name}",
                        e
                    )
            else:
                def show_info_message(plugin):
                    Msg.show_info(
                        CParserTask.__class__,
                        plugin.get_dialog().get_component(),
                        "Parse Errors",
                        "File was not created due to parse errors."
                    )

                Thread(target=show_info_message, args=(plugin)).start()
        except ParseException as e:
            print(f"Error: {e}")
            def show_info_message(plugin):
                Msg.show_info(
                    CParserTask.__class__,
                    plugin.get_dialog().get_component(),
                    "Parse Errors",
                    str(e)
                )

            Thread(target=show_info_message, args=(plugin)).start()
        except Exception as e:
            print(f"Error: {e}")
            Msg.show_error(self, plugin.get_dialog().get_component(), "Error During Parse", "Parse header files failed", e)

class ParseException(Exception):
    pass
