Here is a translation of the Java code into equivalent Python code:

```Python
class ExchangeRatesFragment:
    def __init__(self):
        self.activity = None
        self.application = None
        self.config = None
        self.view_group = None
        self.recycler_view = None
        self.adapter = None
        self.viewModel = None

    def on_attach(self, context):
        super().onAttach(context)
        self.activity = context
        self.application = activity.get_wallet_application()
        self.config = application.get_configuration()

    def on_create(self, savedInstanceState):
        super().onCreate(savedInstanceState)
        set_has_options_menu(True)

        self.viewModel = ViewModelProvider(self).get(ExchangeRatesViewModel())
        if config.is_enable_exchange_rates():
            self.viewModel.get_exchange_rates().observe(self, exchange_rates ->
                if not exchange_rates.empty:
                    view_group.set_displayed_child(2)
                    maybe_submit_list()

                    initial_exchange_rate = viewModel.get_initial_exchange_rate()
                    if initial_exchange_rate is not None:
                        # The delay is needed because of the list needs time to populate.
                        Handler().postDelayed(lambda: viewModel.selected_exchange_rate.set(initial_exchange_rate), 250)

                    if activity instanceof ExchangeRatesActivity:
                        source = exchange_rates.iterator().next().get_source()
                        activity.get_action_bar().set_subtitle(get_string(R.string.exchange_rates_fragment_source, source))
                else if exchange_rates.empty and viewModel.is_constrained():
                    view_group.set_displayed_child(1)
                else:
                    view_group.set_displayed_child(0)

            )
        )

    def on_create_view(self, inflater, container, savedInstanceState):
        view = inflater.inflate(R.layout.exchange_rates_fragment, container, False)
        self.view_group = view.find(R.id.exchange_rates_list_group)
        self.recycler_view = view.find(R.id.exchange_rates_list)
        self.recycler_view.set_has_fixed_size(True)
        self.recycler_view.set_layout_manager(LinearLayoutManager(activity))
        self.recycler_view.setAdapter(self.adapter)

    def on_destroy(self):
        config.unregister_on_shared_preference_changed_listener(self)
        super().onDestroy()

    def maybe_submit_list(self):
        exchange_rates = viewModel.get_exchange_rates().get()
        if exchange_rates is not None:
            adapter.submit_list(ExchangeRatesAdapter.build_list_items(exchange_rates, viewModel.get_balance().get(), application.blockchain_state.get(), config.get_exchange_currency_code(), config.get_btc_base()))

    def on_exchange_rate_click(self, view, exchange_rate_code):
        self.viewModel.selected_exchange_rate.set(exchange_rate_code)

    def on_inflate_block_context_menu(self, inflater, menu):
        inflater.inflate(R.menu.exchange_rates_context, menu)

    def on_click_block_context_item(self, item, exchange_rate_code):
        if item.get_id() == R.id.exchange_rates_context_set_as_default:
            config.set_exchange_currency_code(exchange_rate_code)
            return True
        else:
            return False

    def on_create_options_menu(self, menu, inflater):
        inflater.inflate(R.menu.exchange_rates_fragment_options, menu)

        search_item = menu.find(R.id.exchange_rates_options_search)
        if config.is_enable_exchange_rates():
            search_view = (SearchView) search_item.get_action_view()
            search_view.set_on_query_text_listener(lambda text: self.viewModel.set_constraint(text.trim()) and maybe_submit_list())
            search_view.set_on_query_text_submitted(lambda query: search_view.clear_focus() and True)
        else:
            search_item.setVisible(False)

    def on_shared_preference_changed(self, shared_preferences, key):
        if Configuration.PREFS_KEY_EXCHANGE_CURRENCY == key:
            self.maybe_submit_list()
        elif Configuration.PREFS_KEY_BTC_PRECISION == key:
            self.maybe_submit_list()

```

Note that this is a direct translation of the Java code into Python.