from kivy.app import App
from kivy.uix.recyclerview import RecycleView
from android.content.pm import PackageManager
from android.os import Build, Bundle

class SettingsActivity(App):
    def build(self):
        if Build.VERSION.SDK_INT >= 29:
            self.window.getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION)
            self.window.setNavigationBarColor(Color.TRANSPARENT)

        super(SettingsActivity, self).build()

        Prefs.init_defaults(self.context)

        self.setContentView(R.layout.settings_activity)
        if savedInstanceState is None:
            self.getSupportFragmentManager().beginTransaction()
                .replace(R.id.settings, SettingsFragment())
                .commit()

        actionBar = self.getActionbar()
        if actionBar is not None:
            actionBar.setDisplayHomeAsUpEnabled(True)

        if Build.VERSION.SDK_INT >= 29:
            layout = findViewById(R.id.settings_layout)
            layout.setOnApplyWindowInsetsListener(
                lambda view, window_insets: (
                    view.setPadding(window_insets.getSystemWindowInsetLeft(),
                        window_insets.getSystemWindowInsetTop(),
                        window_insets.getSystemWindowInsetRight(), 0),
                    if recyclerView is not None:
                        recyclerView.setPadding(0, 0, 0, window_insets.getSystemWindowInsetBottom())
                    return window_insets
                )
            )

    def on_create(self, savedInstanceState):
        super(SettingsActivity, self).onCreate(savedInstanceState)

class SettingsFragment(AppCompatActivity):
    def onCreatePreferences(self, savedInstanceState, root_key):
        set_preferences_from_resource(R.xml.root_preferences, root_key)
        
        preference_auto_pip = find_preference("auto_piP")
        if preference_auto_pip is not None:
            preference_auto_pip.setEnabled(Utils.is_piPSupported(self.get_context()))

        preference_frame_rate_matching = find_preference("frameRateMatching")
        if preference_frame_rate_matching is not None:
            preference_frame_rate_matching.setEnabled(Build.VERSION.SDK_INT >= 23)

    def on_view_created(self, view, savedInstanceState):
        super(SettingsFragment, self).onViewCreated(view, savedInstanceState)
        
        if Build.VERSION.SDK_INT >= 29:
            recyclerView = get_list_view()
