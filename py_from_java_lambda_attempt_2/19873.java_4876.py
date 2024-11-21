Here is the translation of the Java code into Python:

```Python
class SkriptConfig:
    def __init__(self):
        pass

main_config = None
configs = []

version_option = Option("version", "1.0")
language_option = Option("language", "english")

check_for_new_version_option = Option("check for new version", False)
update_check_interval_option = Option("update check interval", 12 * 60 * 60 * 1000)

updater_download_tries_option = Option("updater download tries", 7, optional=True)
release_channel_option = Option("release channel", "none")

# Legacy updater options. They have no effect
automatically_download_new_version_option = Option("automatically download new version", False, optional=True)
update_to_prereleases_option = Option("update to pre-releases", True, optional=True)

enable_effect_commands_option = Option("enable effect commands", False)
effect_command_token_option = Option("effect command token", "!")
allow_ops_to_use_effect_commands_option = Option("allow ops to use effect commands", False)

databases_section = OptionSection("databases")

use_player_uuids_in_variable_names_option = Option("use player UUIDs in variable names", False, optional=True)
enable_player_variable_fix_option = Option("player variable fix", True, optional=True)

short_date_format = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
date_format_option = Option("date format", short_date_format, converter=Converter(str))

verbosity_option = Option("verbosity", Verbosity.NORMAL, enum_parser=EnumParser(Verbosity))
default_event_priority_option = Option("plugin priority", EventPriority.NORMAL, converter=Converter(str))

log_player_commands_option = Option("log player commands", False)
number_accuracy_option = Option("number accuracy", 2)

max_target_block_distance_option = Option("maximum target block distance", 100)

case_sensitive_option = Option("case sensitive", False)
allow_functions_before_defs_option = Option("allow function calls before definations", False, optional=True)

disable_variable_conflict_warnings_option = Option("disable variable conflict warnings", False)
disable_object_cannot_be_saved_warnings_option = Option("disable variable will not be saved warnings", False)
disable_missing_and_or_warnings_option = Option("disable variable missing and/ or warnings", False)
disable_variable_starting_with_expression_warnings_option = Option("disable starting a variable's name with an expression warnings", False)

execute_functions_with_missing_params_option = Option("execute functions with missing parameters", True, optional=True)

def get_config():
    return main_config

load_configs = []

@staticmethod
def load(config_file):
    try:
        config = Config(config_file, False, False, ":")
        if not Skript.get_version().toString() == config.get(version_option.key):
            new_config = Config(None, "Skript.jar/config.sk", False, False, ":")
            in_stream = Skript.getInstance().getResource("config.ck")
            if in_stream is None:
                print(f"Your config is outdated, but Skript couldn't find the newest config in its jar.")
                return False
            new_config_values = new_config.get_main_node()
            main_node = config.get_main_node()
            databases_section_value = main_node.get(databases_option.key)
            if databases_section_value:
                new_config_values.set(databases_option.key, databases_section_value)
            config = main_config = new_config
            config.save(config_file)
        else:
            config.get_main_node().set(version_option.key, Skript.get_version().toString())
            config.save(config_file)
    except Exception as e:
        print(f"An error occurred while loading the config: {e}")
        return False

@staticmethod
def get_date_format():
    return date_format_option.value()

@staticmethod
parse_links_option = Option("parse links in chat messages", "disabled")
setter=lambda s: ChatMessages.link_parse_mode(s)

case_insensitive_variables_option = Option("case-insensitive variables", True, optional=True)
setter=lambda t: Variables.case_insensitive_variables(t)

color_reset_codes_option = Option("color codes reset formatting", True)
setter=lambda t: try:
    if t:
        ChatMessages.color_reset_codes()
except Exception as e:
    print(f"An error occurred while setting color reset codes: {e}")

script_loader_thread_size_option = Option("script loader thread size", "0")
setter=lambda s: int(s) if s.isdigit() else Runtime.getRuntime().availableProcessors()

allow_unsafe_platforms_option = Option("allow unsafe platforms", False, optional=True)

keep_last_usage_dates_option = Option("keep command last usage dates", False)
load_default_aliases_option = Option("load default aliases", True, optional=True)

disable_hook_vault_option = Option("disable hooks.vault", False, optional=True)
setter=lambda t: if t:
    Skript.disable_hook_registration(VaultHook.class)

disable_hook_grief_prevention_option = Option("disable hooks.regions.grief prevention", False, optional=True)
setter=lambda t: if t:
    Skript.disable_hook_registration(GriefPreventionHook.class)

disable_hook_precious_stones_option = Option("disable hooks.regions.precious stones", False, optional=True)
setter=lambda t: if t:
    Skript.disable_hook_registration(PreciousStonesHook.class)

disable_hook_residence_option = Option("disable hooks.regions.residence", False, optional=True)
setter=lambda t: if t:
    Skript.disable_hook_registration(ResidenceHook.class)

disable_hook_world_guard_option = Option("disable hooks.regions.worldguard", False, optional=True)
setter=lambda t: if t:
    Skript.disable_hook_registration(WorldGuardHook.class)