class VersionControlCheckOutAction:
    def __init__(self, plugin):
        self.plugin = plugin
        self.resource_manager = ResourceManager()

    def create_action(self, owner, tool):
        super("Check Out", owner, tool)
        icon = self.resource_manager.load_image("images/vcCheckOut.png")
        set_popup_menu_data(new MenuData(["Check Out"], icon, "GROUP"))
        set_tool_bar_data(new ToolBarData(icon, "GROUP"))
        description = "Checkout file"
        enabled = False

    def action_performed(self, context):
        self.check_out(context.get_selected_files())

    def is_enabled_for_context(self, context):
        if self.is_file_system_busy():
            return False
        provided_list = context.get_selected_files()
        for domain_file in provided_list:
            if domain_file.can_checkout():
                return True
        return False

    def get_user(self):
        try:
            if self.repository is not None:
                user = self.repository.get_user()
                return user
        except IOException as e:
            ClientUtil.handle_exception(self.repository, e, "Check Out", tool.get_tool_frame())
        return None

    def check_out(self, files):
        if not self.check_repository_connected():
            return
        self.tool.execute(CheckOutTask(files))

class CheckOutTask(Task):
    def __init__(self, files):
        super("Checkout Task")
        self.files = files
        self.exclusive = True
        self.checkout_dialog = None

    def gather_versioned_files(self, monitor, results):
        monitor.set_message("Examining Files...")
        monitor.set_maximum(len(files))
        for df in files:
            if df.is_versioned() and not df.is_checked_out():
                results.append(df)
            monitor.increment_progress(1)

        n = len(results)
        if n == 0:
            Msg.show_error(self, tool.get_tool_frame(), "Checkout Failed", 
                            "The specified files do not contain any versioned files available for checkout")
            return False

        user = self.get_user()
        if user is not None and user.has_write_permission():
            self.checkout_dialog = Swing.run_now(lambda: CheckoutDialog())
            if self.checkout_dialog.show_dialog(tool) != CheckoutDialog.OK:
                return False
            self.exclusive = self.checkout_dialog.exclusive_checkout()
            return True

        if n == 1:
            return True

        choice = OptionDialog.show_yes_no_dialog_with_no_as_default_button(
                    tool.get_tool_frame(), "Confirm Bulk Checkout", 
                    f"Would you like to checkout {n} files as specified?")
        return choice == OptionDialog.YES_OPTION

    def run(self, monitor):
        try:
            versioned_files = []
            if not self.gather_versioned_files(monitor, versioned_files):
                return
            monitor.set_maximum(0)
            monitor.set_progress(0)

            wrapped_monitor = WrappingTaskMonitor(monitor)
            failed_checkouts = []

            for df in versioned_files:
                if not df.checkout(self.exclusive, wrapped_monitor):
                    failed_checkouts.append(df)
            show_results_message(versioned_files, failed_checkouts)
        except CancelledException as e:
            tool.set_status_info("Checkout cancelled")
        except IOException as e:
            ClientUtil.handle_exception(self.repository, e, "Check Out", tool.get_tool_frame())

    def show_results_message(self, all_files, failed_files):
        total = len(all_files)
        if not failed_files:
            s = f"Checkout completed for {total} file(s)"
            tool.set_status_info(s)
            Msg.info(self, s)
            return

        if len(failed_files) == 1:
            df = failed_files[0]
            user_message = f"Exclusive checkout failed for: {df.name}\nOne or more users have file checked out!"
            Msg.show_error(self, tool.get_tool_frame(), "Checkout Failed", user_message)
            return

        message = "Multiple exclusive checkouts failed.\nOne or more users have file checked out!"
        buffy = StringBuilder(message + '\n')
        for df in failed_files:
            formatted = f"Exclusive checkout failed for: {df.name}\n"
            buffy.append(formatted)

        Msg.show_error(self, tool.get_tool_frame(), "Checkout Failed", message + "\n(see log for list of failed files)")
