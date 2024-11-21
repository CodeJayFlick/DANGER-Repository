class RootNode:
    def __init__(self):
        self.tool_name = None
        self.child = None
        self.detached_windows = []
        self.status_bar = None
        self.window_wrapper = None
        self.drop_target_factory = None

    @property
    def tool_name(self):
        return self._tool_name

    @tool_name.setter
    def tool_name(self, value):
        self._tool_name = value

    def __init__(self, win_mgr, tool_name, images, is_modal, drop_target_factory):
        super().__init__()
        self.tool_name = tool_name
        self.detached_windows = []
        if is_modal:
            frame = HiddenDockingFrame(tool_name)
            set_frame_icon(frame, images)
            dialog = create_dialog(tool_name, frame)
            window_wrapper = JDialogWindowWrapper(None, dialog)  # change to a dialog type
        else:
            frame = DockingFrame(tool_name)
            set_frame_icon(frame, images)
            window_wrapper = JFrameWindowWrapper(frame)

    def create_dialog(self, title, frame):
        return JDialog(frame, True)

    def set_frame_icon(self, frame, image):
        if Platform.CURRENT_PLATFORM.get_operating_system() == OperatingSystem.MAC_OS_X:
            pass
        else:
            frame.set_icon_images([image])

    # ... (other methods similar to the above ones)
