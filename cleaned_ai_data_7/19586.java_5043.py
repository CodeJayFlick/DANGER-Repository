class HoverList:
    def __init__(self):
        self.PAPER_EVENT_EXISTS = hasattr(com.destroystokyo.paper.event.server.PaperServerListPingEvent, '__module__')

    @property
    def name(self):
        return "Hover List"

    @property
    def description(self):
        return ["The list when you hover on the player counts of the server in the server list.",
                "This can be changed using texts or players in a <a href='events.html#server_list_ping'>server list ping</a> event only."
               + "Adding players to the list means adding the name of the players.",
                "And note that, for example if there are 5 online players (includes fake online count) "
               + "in the server and the hover list is set to 3 values, Minecraft will show \"... and 2 more ...\" at end of the list."]

    @property
    def examples(self):
        return ["on server list ping:",
                "\tclear the hover list",
                "\tadd \"&aWelcome to the &6Minecraft &aserver!\" to the hover list",
                "\tadd \"\" to the hover list  # A blank line",
                "\tadd \"&cThere are &6%online players count% &conline players!\" to the hover list"]

    @property
    def since(self):
        return "2.3"

    @property
    def required_plugins(self):
        return ["Paper 1.12.2 or newer"]

    @property
    def events(self):
        return ["server list ping"]

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not self.PAPER_EVENT_EXISTS:
            print("The hover list expression requires Paper 1.12.2 or newer")
            return False

        elif not get_parser().is_current_event(com.destroystokyo.paper.event.server.PaperServerListPingEvent):
            print("The hover list expression can't be used outside of a server list ping event")
            return False
        return True

    def get(self, e):
        if isinstance(e, com.destroystoy.paper.event.server.PaperServerListPingEvent):
            player_sample = ((PaperServerListPingEvent) e).get_player_sample()
            return [player_profile.get_name() for player_profile in player_sample]

    def accept_change(self, mode):
        if get_parser().has_delay_before():
            print("Can't change the hover list anymore after the server list ping event has already passed")
            return None

        switch = {
            ChangeMode.SET: CollectionUtils.array(String[].class, Player[].class),
            ChangeMode.ADD: CollectionUtils.array(String[].class, Player[].class),
            ChangeMode.REMOVE: CollectionUtils.array(String[].class, Player[].class),
            ChangeMode.DELETE: None,
            ChangeMode.RESET: None
        }
        return switch.get(mode)

    def change(self, e, delta, mode):
        if mode not in [ChangeMode.DELETE, ChangeMode.RESET]:
            for o in delta:
                if isinstance(o, com.destroystokyo.paper.player.Player):
                    player = ((Player) o)
                    values.append(Bukkit.create_profile(player.get_unique_id(), player.get_name()))
                else:
                    values.append(Bukkit.create_profile(UUID.random_uuid(), str(o)))

        sample = ((PaperServerListPingEvent) e).get_player_sample()
        switch = {
            ChangeMode.SET: lambda: sample.clear().extend(values),
            ChangeMode.ADD: lambda: sample.extend(values),
            ChangeMode.REMOVE: lambda: sample.remove(*values),
            ChangeMode.DELETE: None,
            ChangeMode.RESET: lambda: sample.clear()
        }
        return switch.get(mode)()

    def is_single(self):
        return False

    def get_return_type(self):
        return str
