class AcceptMatchTask:
    def __init__(self, controller: 'VTController', matches: list) -> None:
        self.controller = controller
        self.matches = matches
        super().__init__("Accept Matches", controller.get_session())

    @property
    def do_apply_function_names(self):
        return self._do_apply_function_names

    @do_apply_function_names.setter
    def do_apply_function_names(self, value: bool) -> None:
        if not isinstance(value, bool):
            raise ValueError("Value must be a boolean")
        self._do_apply_function_names = value

    @property
    def do_apply_data_names(self):
        return self._do_apply_data_names

    @do_apply_data_names.setter
    def do_apply_data_names(self, value: bool) -> None:
        if not isinstance(value, bool):
            raise ValueError("Value must be a boolean")
        self._do_apply_data_names = value

    def should_suspend_session_events(self) -> bool:
        return len(self.matches) > 20

    def do_work(self, monitor: 'TaskMonitor') -> bool:
        destination_program = self.controller.get_destination_program()
        auto_analysis_manager = AutoAnalysisManager.get_analysis_manager(destination_program)
        try:
            analysis_worker_callback(analysis_worker=AutoAnalysisWorker(),
                                       program=destination_program,
                                       worker_context=None,
                                       task_monitor=monitor)
            return True
        except CancelledException as e:
            # don't care
            pass
        except Exception as e:
            self.report_error(e)

    def accept_matches(self, monitor: 'TaskMonitor') -> None:
        for match in self.matches:
            if match.get_association().get_status() != VTAssociationStatus.AVAILABLE:
                continue

            self.accept_match(match)
            if do_apply_function_names and match.get_association_type() == VTAssociationType.FUNCTION:
                apply_function_names(match, monitor)
            elif do_apply_data_names and match.get_association_type() == VTAssociationType.DATA:
                apply_data_names(match, monitor)

    def accept_match(self, match: 'VTMatch') -> None:
        association = match.get_association()
        status = association.get_status()

        if status == VTAssociationStatus.ACCEPTED:
            return

        try:
            association.set_accepted()
        except VTAssociationStatusException as e:
            raise AssertException(f"Should have been given an association that is not blocked - current status: {association.status}")

    def apply_data_names(self, match: 'VTMatch', monitor: 'TaskMonitor') -> None:
        association = match.get_association()
        markup_items = association.get_markup_items(monitor)
        vt_markup_item = self.get_data_label_markup_item(association.get_source_address(), markup_items)

        if vt_markup_item is not None and do_apply_data_names:
            try:
                vt_markup_item.apply(VTMarkupItemApplyActionType.REPLACE, self.controller.get_options())
            except VersionTrackingApplyException as e:
                self.report_error(e)

    def apply_function_names(self, match: 'VTMatch', monitor: 'TaskMonitor') -> None:
        association = match.get_association()
        markup_items = association.get_markup_items(monitor)
        vt_markup_item = self.get_function_name_markup_item(markup_items)

        if vt_markup_item is not None and do_apply_function_names:
            try:
                vt_markup_item.apply(VTMarkupItemApplyActionType.REPLACE, self.controller.get_options())
            except VersionTrackingApplyException as e:
                self.report_error(e)

    def get_data_label_markup_item(self, source: 'Address', markup_items: list) -> 'VTMarkupItem':
        for item in markup_items:
            if item.get_markup_type() == LabelMarkupType.INSTANCE and item.get_source_address().equals(source):
                return item

        return None

    def get_function_name_markup_item(self, markup_items: list) -> 'VTMarkupItem':
        for item in markup_items:
            if item.get_markup_type() == FunctionNameMarkupType.INSTANCE:
                return item

        return None
