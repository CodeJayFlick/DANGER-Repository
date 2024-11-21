class MaybeMaintenanceFragment:
    FRAGMENT_TAG = type('FRAGMENT_TAG', (object,), {}).__name__

    @classmethod
    def add(cls, fm):
        fragment = fm.find_fragment_by_tag(MaybeMaintenanceFragment.FRAGMENT_TAG)
        if not isinstance(fragment, type):
            fragment = cls()
            fm.begin_transaction().add(fragment, MaybeMaintenanceFragment.FRAGMENT_TAG).commit()

    def __init__(self):
        self.viewModel = None

    def onCreate(self, savedInstanceState):
        super().__init__()
        self.viewModel = ViewModelProvider(self).get(MaybeMaintenanceViewModel)
        self.viewModel.show_dialog.observe(self, lambda v: 
            if not self.viewModel.get_dialog_was_shown():
                MaintenanceDialogFragment.show(get_parent_fragment_manager())
                self.viewModel.set_dialog_was_shown()
)

