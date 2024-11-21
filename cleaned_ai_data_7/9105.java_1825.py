class VTSessionContentHandler:
    CONTENT_TYPE = None


def vt_session_filter(domain_file):
    return domain_file.get_content_type() == VTSessionContentHandler.CONTENT_TYPE


def program_db_filter(domain_file):
    return domain_file.get_content_type() == ProgramDB().CONTENT_TYPE


def choose_domain_file(parent, domain_identifier, filter=None, file_to_select=None):
    data_tree_dialog = DataTreeDialog(parent, f"Choose {domain_identifier}", "OPEN")
    
    if filter:
        data_tree_dialog.set_filter(filter)

    box = {"df": None}

    def ok_action_listener(event):
        nonlocal box
        box["df"] = data_tree_dialog.get_domain_file()
        if box["df"]:
            data_tree_dialog.close()

    data_tree_dialog.add_ok_action_listener(ok_action_listener)
    
    data_tree_dialog.select_domain_file(file_to_select)
    data_tree_dialog.show_component()
    
    return box["df"]


def ask_user_to_save(parent, domain_file):
    filename = domain_file.name
    result = OptionDialog.show_yes_no_dialog(parent, "Save Version Tracking Changes?",
                                              f"Unsaved Version Tracking changes found for session: {HTMLUtilities.escape_html(filename)}. Would you like to save these changes?")

    do_save = result == OptionDialog.YES_OPTION

    if do_save:
        save_task = SaveTask(domain_file)
        TaskLauncher(save_task, parent).start()
        
        return save_task.did_save()

    return False


def ask_user_to_save_before_closing(parent, domain_file):
    filename = domain_file.name
    result = OptionDialog.show_yes_no_cancel_dialog(parent, "Save Version Tracking Changes?",
                                                     f"Unsaved Version Tracking changes found for session: {HTMLUtilities.escape_html(filename)}. Would you like to save these changes?")

    if result == OptionDialog.CANCEL_OPTION:
        return False

    do_save = result == OptionDialog.YES_OPTION
    if do_save:
        save_task = SaveTask(domain_file)
        TaskLauncher(save_task, parent).start()
        
        return save_task.did_save()

    return True


class DomainFileBox:
    def __init__(self):
        self.df = None

