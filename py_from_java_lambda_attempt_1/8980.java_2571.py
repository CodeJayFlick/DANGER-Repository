Here is the translation of the given Java code into Python:

```Python
class MatchStatusUpdaterAssociationHook:
    def __init__(self, controller):
        self.controller = controller
        self.session = None
        self.controller.add_listener(self)

    def association_accepted(self, association):
        self.update_markup_status(association)

    def association_cleared(self, association):
        association.set_markup_status(VTAssociationMarkupStatus())

    def markup_item_status_changed(self, markup_item):
        self.controller.markup_item_status_changed(markup_item)
        self.update_markup_status(markup_item.get_association())

    def session_changed(self, new_session):
        if self.session is not None:
            self.session.remove_association_hook(self)
        self.session = new_session
        if self.session is not None:
            self.session.add_association_hook(self)

    def update_markup_status(self, association):
        matches = association.get_session().get_matches(association)
        if len(matches) == 0:
            return

        markup_items = []
        try:
            for match in matches:
                markup_items.extend(match.get_association().get_markup_items())
            applied_count = sum(1 for item in markup_items if item.status in [VTMarkupItemStatus.ADDED, VTMarkupItemStatus.REPLACED])
            rejected_count = sum(1 for item in markup_items if item.status == VTMarkupItemStatus.REJECTED)
            unapplied_count = len(markup_items) - applied_count - rejected_count
            association.set_markup_status(VTAssociationMarkupStatus(applied_count > 0, 
                                                                     rejected_count > 0,
                                                                     unapplied_count > 0))
        except CancelledException:
            pass

    def get_applied_markup_status(self, markup_items):
        applied_count = sum(1 for item in markup_items if item.status in [VTMarkupItemStatus.ADDED, VTMarkupItemStatus.REPLACED])
        rejected_count = sum(1 for item in markup_items if item.status == VTMarkupItemStatus.REJECTED)
        unapplied_count = len(markup_items) - applied_count - rejected_count
        return VTAssociationMarkupStatus(applied_count > 0,
                                            rejected_count > 0,
                                            unapplied_count > 0)

    def disposed(self):
        pass

    def markup_item_selected(self, markup_item):
        pass

    def match_selected(self, match_info):
        pass

    def options_changed(self, options):
        pass

    def session_updated(self, ev):
        pass
```

Note: The `VTAssociationMarkupStatus`, `VTMarkupItemStatus` and other classes are not defined in the given Java code. They should be replaced with Python equivalents or implemented according to your requirements.