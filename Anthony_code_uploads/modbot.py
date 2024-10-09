import fol_interface
import game_state
import discord_interface
import roles
import player as p
import post as post_class
import roles_folder.host as host
import config

import os
import random
import time
import asyncio
import inspect
import datetime

INVALID_FLIP = "This flip is invalid, and should never be posted. If you are seeing this, it is in error."


assert config.day_length > config.action_deadline and config.night_length > config.action_deadline
assert config.action_deadline >= 1

rolelist = [roles.make_day_vig] * 2 + [roles.make_mafia_goon]


# Gamestate Variables Start (do not change unless debugging) (also includes program state variables)
is_day = True
phase_count = 1
nightkill_choice = ''
continue_posting_vcs = True
posts_in_thread_at_last_vc = -1
game_started = False
action_submission_open = False
game_end_announced_already = False
# Gamestate Variables End

# Warnings Begin

if not config.rand_roles:
    print("Roles are NOT randomized! If this is used in actual play, roles must be randomized.")

# Warnings End

# Main program begin

if config.rand_roles:
    random.seed(time.time())
    random.shuffle(rolelist)

mafia_list = []

playerlist_player_objects = []

for num in range(len(rolelist)):
    username = config.playerlist_usernames[num]
    playerlist_player_objects.append(rolelist[num](username))
    if playerlist_player_objects[num].alignment == game_state.MAFIA:
        mafia_list.append(username)



gamestate = game_state.GameState(playerlist_player_objects,
                                 is_day=is_day,
                                 phase_count=phase_count,
                                 wincon_is_parity=True)

capitalization_fixer = dict()
for player in config.playerlist_usernames:
    capitalization_fixer[player.lower()] = player

async def announce_game_end(mafia_list: list[str]):
    global continue_posting_vcs
    global game_end_announced_already

    if game_end_announced_already:
        return None
    await asyncio.sleep(5)
    print(mafia_list)
    await fol_interface.announce_winner(gamestate.is_town_win(), mafia_members=mafia_list)
    continue_posting_vcs = False
    game_end_announced_already = True
    return None

def process_nightkill(nightkill_username: str, gamestate: game_state.GameState):
    """
    Processes the nightkill.

    Parameters:

    - nightkill_username - The username of the player to be nightkilled; must be valid.
    - gamestate - The current gamestate
    """
    player_object = gamestate.get_player_object(nightkill_username)
    assert player_object is not None
    player_object.take_damage(1)

def process_elimination(eliminated_player_username: str, gamestate: game_state.GameState, was_tie: bool):
    flip = get_flip(eliminated_player_username, gamestate)
    gamestate.process_elimination(eliminated_player_username)
    print(f"Day {gamestate.phase_count} has just ended.")
    if eliminated_player_username != fol_interface.NO_EXE:
        fol_interface.post_cache_elimination(
            capitalization_fixer[eliminated_player_username.lower()], 
            was_tie,
            flip, 
            living_players=gamestate.get_living_players(), )
        fol_interface.send_message("# You have died.", eliminated_player_username)
    else:
        fol_interface.post_cache_no_exe(was_tie=was_tie,
                                    living_players=gamestate.get_living_players(),
                                )


async def resolve_day_or_night_end_actions(elimination_or_nightkill: str, gamestate: game_state.GameState, was_tie: bool, is_day: bool):
    """
    elimination_or_nightkill - The player who's voted out or nightkilled
    gamestate - The gamestate object
    was_tie - True if this was an elimination that randed, False otherwise
    is_day - True if a day just ended, False if night ended
    """
    actions_to_be_resolved_at_phase_end = [] #Entries here are (ability object, [acting player object,
                                         # gamestate, parameters from syntax parser], ability priority)


    for player in gamestate.players:
        for unresolved_action in player.unresolved_actions:
            ability_object = p.all_abilities[unresolved_action.ability_id]
            actions_to_be_resolved_at_phase_end.append([ability_object, 
                                                        [player, gamestate, unresolved_action.parameters], 
                                                        ability_object.ability_priority])

    actions_to_be_resolved_at_phase_end.append([lambda *args : None, [], 0]) 
    # Above ensures there's an action with priority=0, so the elimination/nightkill is processed
    actions_to_be_resolved_at_phase_end.sort(key=lambda x : x[2])

    exe_or_nightkill_processed = False

    for ability, parameters, priority in actions_to_be_resolved_at_phase_end:
        assert type(ability) == p.Ability
        parameters[2] = process_redirects(parameters[2], ability) #parameters[2] is the output of the syntax parser
        action_function = ability.use_action_phase_end
        if priority >= 0 and not exe_or_nightkill_processed:
            if is_day:
                process_elimination(elimination_or_nightkill, gamestate, was_tie)
            else:
                process_nightkill(elimination_or_nightkill, gamestate=gamestate)
            exe_or_nightkill_processed = True
        acting_player = parameters[0]
        assert type(acting_player) == p.Player
        if ability.willpower_required_instant is None or acting_player.willpower >= ability.willpower_required_instant:
            possible_awaitable = action_function(parameters[0], parameters[1], *parameters[2])
            if inspect.isawaitable(possible_awaitable):
                await possible_awaitable
            ability.phase_end_use_count += 1
    
    actions_to_be_resolved_at_phase_end = []

    
    resolve_current_deaths(gamestate, during_night_death_flavor=not is_day)

    gamestate.go_next_phase()
    await asyncio.sleep(2)


def resolve_current_deaths(gamestate: game_state.GameState, during_night_death_flavor=False):
    """
    Kills all players whose health is at 0, and posts the deaths in the thread. This also posts anything in the cache, which
    can be used for death flavor / shot announcements.

    Players whose health is at 0 should always die immediately, so this should be called after any damage is dealt to a player,
    in case they die.
    """
    about_to_die_players = gamestate.list_about_to_die_players()
    
    for about_to_die_player in about_to_die_players:
        flip = get_flip(about_to_die_player, gamestate)
        fol_interface.add_death_to_cache(about_to_die_player, f"has died{' during the night' if during_night_death_flavor else ''}!\n", flip)
        fol_interface.send_message("# You have died.", about_to_die_player)

    gamestate.kill_about_to_die_players()

    if len(about_to_die_players) > 0:
        fol_interface.to_post_cache += fol_interface.ping_string(gamestate.get_living_players(), include_alive_tags=True)
    fol_interface.post_cache()

def resolve_name(nickname: str):
    """
    Removes an '@' before the name, and resolves by substring if needed.
    Details of substring resolution are explained in fol_interface.resolve_substring_alias, with `for_votecount == False`.
    """
    if len(nickname) > 0:
        nickname = nickname[1:] if nickname[0] == '@' else nickname
    return fol_interface.resolve_substring_alias(nickname, gamestate.get_living_players(), for_votecount=False)
    

def get_pregame_post_string():
    with open("about_zugbot.md", "r") as about_zugbot_file:
        pregame_post_string = about_zugbot_file.read()

    pregame_post_string += "# Parameters for this game \n"
    pregame_post_string += f"Day length: {config.day_length} minutes \n"
    pregame_post_string += f"Night length: {config.night_length} minutes \n"
    pregame_post_string += f"Action Deadline: {config.action_deadline} minutes before phase change \n"
    pregame_post_string += f"Multivoting allowed: {config.allow_multivoting} \n"
    pregame_post_string += f"No-Exe allowed: {config.allow_no_exe} \n"
    if config.allow_no_exe:
        pregame_post_string += f"No-Exe wins ties: {config.no_exe_wins_ties} \n"
    pregame_post_string += f"Minimum Delay Between Votecounts: {config.votecount_time_interval}\n"
    pregame_post_string += f"Minimum Postcount Between Votecounts: {config.votecount_post_interval}\n"
    
    return pregame_post_string

def submit_nightkill(player_to_kill: str) -> bool:
    global nightkill_choice
    if not gamestate.is_day and gamestate.is_valid_nightkill(player_to_kill):
        nightkill_choice = capitalization_fixer[player_to_kill.lower()]
        return True
    return False

def get_flip(player: str, gamestate: game_state.GameState):
    print(f"Getting flip for {player}")
    if not gamestate.player_exists(player):
        return INVALID_FLIP
    flip_path = os.path.join(config.flips_folder, gamestate.get_flip_path(player))
    with open(flip_path, 'r') as flip_file:
        return flip_file.read()

async def give_role_pms(playerlist: list[str], gamestate: game_state.GameState):
    for player in playerlist:
        flip = get_flip(player, gamestate)
        await fol_interface.give_role_pm(player, flip, config.game_name, 
                                         discord_links=[config.mafia_discord_link] if gamestate.player_is_mafia(player) else [], 
                                         teammates=mafia_list if gamestate.player_is_mafia(player) else None)
        
async def run_vc_bot():
    global posts_in_thread_at_last_vc
    global continue_posting_vcs
    while continue_posting_vcs:
        await asyncio.sleep(config.votecount_time_interval * 60)
        new_postcount = int(await fol_interface.get_number_of_posts_in_thread(topic_id=config.topic_id))
        if gamestate.is_day and game_started and new_postcount - posts_in_thread_at_last_vc > config.votecount_post_interval and continue_posting_vcs:
            await fol_interface.post_votecount()
            posts_in_thread_at_last_vc = new_postcount
    return None

def topic_is_pm(topic_number_parameter: str | int, username: str):
    return int(topic_number_parameter) == int(fol_interface.username_to_role_pm_id[username.lower()])

def topic_is_main_thread(topic_number_parameter: str | int):
    return config.topic_id == int(topic_number_parameter)

def is_submission_location_correct(submission_location: int, topic_number_parameter: str | int, username: str):
    if int(submission_location) == p.IN_THREAD:
        return topic_is_main_thread(topic_number_parameter)
    elif int(submission_location) == p.IN_PM:
        return topic_is_pm(topic_number_parameter, username=username)
    return False

def send_feedback(feedback_string: str, sources: list[p.Player] | None, receivers: list[p.Player], action_types: list[str], was_instant: bool):

    pass

"""
Overall action processing sequence:

for each ability:
- submission location correct (quit if not)
- can_use_now (quit if not)
- parse post (throw error? quit!)
- acknowledge_and_verify (throw error? quit!)
- for each player mentioned in this ability, process redirects, making a new set of parameters for the instant action
- if willpower_required_instant is high enough -> do instant action. NEVER throws exception.

later

- for each player mentioned in this ability (original submission, not the result of processing redirects for the instant action), 
    process redirects, making a new set of parameters for the delayed action
- if willpower_required_phase_end is high enough -> do delayed action. NEVER throws exception.

"""

def process_redirects(action_parameters: list, ability: p.Ability) -> list:
    """
    This method takes the parameters for an action, and an Ability, and redirects the action's target(s) if needed.

    action_parameters are the parameters for the action, and ability is the Ability.

    This method returns a copy of action_parameters, with the redirects made.

    """
    result = action_parameters.copy()
    for index in range(len(result)):
        if type(result[index]) == p.Player:
            current_focus = ability.target_focus
            current_player = result[index]
            assert type(current_player) == p.Player
            no_more_redirects = False
            while not no_more_redirects:
                next_player = current_player.get_redirect(current_focus)
                current_focus += current_player.get_redirect_focus_increase()
                no_more_redirects = current_player == next_player
                current_player = next_player
            result[index] = current_player
    return result

async def process_post(post: post_class.Post, gamestate: game_state.GameState) -> None:
    player_object = gamestate.get_player_object(username=post.poster)
    if player_object is None and post.poster.lower() != config.host_username.lower():
        print("This player does not exist, or is not alive.")
        return None
    is_host_post = player_object is None
    for ability in (player_object.abilities if not is_host_post else host.host_abilities):
        if not is_submission_location_correct(ability.submission_location, post.topicNumber, post.poster):
            print(f"Submission location for {ability.ability_name} is wrong")
            continue
        print(f"Submission location for {ability.ability_name} is correct")

        if not is_host_post and not ability.can_use_now(player_object, ability, gamestate):
            print(f"{ability.ability_name} cannot be used now.")
            continue
        print(f"{ability.ability_name} can be used now!")
        
        try:
            parameters = ability.syntax_parser(post)
        except roles.ParsingException as e:
            print(f"This message could not be parsed the ability: {ability.ability_name}. Error below: ")
            print(e.args)
            continue
        print(f"Input for {ability.ability_name} parsed successfully; the parameters are {parameters}")

        try:
            possible_awaitable = ability.acknowledge_and_verify(player_object, gamestate, *parameters)
            if inspect.isawaitable(possible_awaitable):
                await possible_awaitable
        except roles.ActionException as e:
            print(f"{post.poster} attempted to use an action with the following parameters: {parameters},"
                  " but it threw an ActionException. Error below:")
            print(e.args)
        
        instant_parameters = process_redirects(parameters, ability)

        if is_host_post or ability.willpower_required_instant is None or player_object.willpower >= ability.willpower_required_instant:
            possible_awaitable = ability.use_action_instant(player_object, gamestate, *instant_parameters)
            if inspect.isawaitable(possible_awaitable):
                await possible_awaitable
            ability.instant_use_count += 1

        if player_object is None:
            print("Note that host abilities cannot have delayed effects at the moment."
                  "If the host ability that was just used was purely instant, disregard this message.")
        else:
            player_object.record_action(ability.id, parameters)

async def run_action_processor():
    action_submission_previously_open = False
    while True:
        await asyncio.sleep(config.action_processor_sleep_seconds)
        if action_submission_open and action_submission_previously_open:
            new_posts = await fol_interface.get_new_posts_with_pings()
            print(f"There are {len(new_posts)} new posts to process")
            for post in new_posts:
                print(f"Processing post by: {post.poster}")
                await process_post(post, gamestate)
                if gamestate.is_game_over():
                    await announce_game_end(mafia_list=mafia_list)
                    return None
        elif action_submission_open and not action_submission_previously_open:
            await fol_interface.get_new_posts_with_pings(ignore_return=True)
            # DON'T process actions here. this is to avoid processing old pings
        action_submission_previously_open = action_submission_open
    
def process_substitution_for_mafia_and_player_lists(current_player: str, new_player: str):
    """
    Corrects playerlist_usernames and mafia_list to include the new player instead of the current player.
    """
    for num, player in enumerate(config.playerlist_usernames):
        if player.lower() == current_player.lower():
            config.playerlist_usernames[num] = new_player
    for num, player in enumerate(mafia_list):
        assert type(player) == str
        if player.lower() == current_player.lower():
            config.playerlist_usernames[num] = new_player

async def wait_for_time(time_datetime: datetime.datetime):
    """
    Given a datetime, sleeps until that time is reached.
    """
    while True:
        seconds_to_sleep = (time_datetime - datetime.datetime.now()).total_seconds() #type: ignore
        if seconds_to_sleep <= 0:
            return None
        print(f"Sleeping for {seconds_to_sleep} seconds")
        await asyncio.sleep(seconds_to_sleep)


async def run_modbot():
    global game_started
    global nightkill_choice
    global continue_posting_vcs
    global action_submission_open
    fol_interface.set_topic_id(new_id=config.topic_id)
    fol_interface.create_post(get_pregame_post_string(), topic_id_parameter=config.topic_id)
    await fol_interface.close_or_open_thread(close=True)
    await asyncio.sleep(5)
    if config.do_role_pms:
        await give_role_pms(playerlist=config.playerlist_usernames, gamestate=gamestate)
    if config.game_start_time != '':
        game_start_time = datetime.datetime.strptime(config.game_start_time, "%Y-%m-%d %H:%M")
        await fol_interface.set_timer(f"{config.game_start_time}{config.utc_offset}", close=False)
        await wait_for_time(game_start_time)

    game_started = True
    while not gamestate.is_game_over():
        if gamestate.is_day: #going into this, gamestate should be day and have all night actions resolved
            
            for player in playerlist_player_objects:
                assert type(player) == p.Player
                player.do_day_start_changes()

            fol_interface.start_day(gamestate.get_living_players(), gamestate.phase_count)
            await fol_interface.close_or_open_thread(close=False)
            if config.game_start_time != "":
                thread_close_time = game_start_time + datetime.timedelta(minutes=(
                    gamestate.phase_count * (config.day_length + config.night_length) - config.night_length))
                actions_close_time = thread_close_time - datetime.timedelta(minutes=config.action_deadline)
                assert type(thread_close_time) == datetime.datetime
                assert type(actions_close_time) == datetime.datetime
                await fol_interface.set_timer(thread_close_time.strftime("%Y-%m-%d %H:%M" + config.utc_offset), close=True)

            action_submission_open = True
            if config.game_start_time != "":
                await wait_for_time(actions_close_time)
            else:
                await asyncio.sleep(60 * (config.day_length - config.action_deadline))
            action_submission_open = False
            if config.game_start_time != "":
                await wait_for_time(thread_close_time + datetime.timedelta(seconds=config.eod_close_delay_seconds)) # type: ignore
            else:
                await asyncio.sleep(60 * config.action_deadline)

            if gamestate.is_game_over(): # in case immediate actions ended the game
                break
            
            await fol_interface.close_or_open_thread(close=True)

            eliminated_player, was_tie = await fol_interface.decide_elimination(allow_multivotes=config.allow_multivoting,
                                                                          allow_no_exe=config.allow_no_exe,
                                                                          no_exe_wins_ties=config.no_exe_wins_ties)
            
            await resolve_day_or_night_end_actions(eliminated_player, gamestate, was_tie, is_day=True)
        else: #going into this, gamestate should be night and have the eliminated player dead
            fol_interface.announce_night_start(phase_number=gamestate.phase_count, living_players=gamestate.get_living_players())
            action_submission_open = True
            await asyncio.sleep(60 * (config.night_length - config.action_deadline))
            action_submission_open = False

            
            # if config.game_start_time != "":
            #     thread_open_time = game_start_time + datetime.timedelta(
            #         minutes=gamestate.phase_count * (config.day_length + config.night_length))
            #     assert type(thread_open_time) == datetime.datetime
            #     await fol_interface.set_timer(thread_open_time.strftime("%Y-%m-%d %H:$M" + config.utc_offset), close=False)
            #     seconds_to_sleep = (thread_open_time - datetime.datetime.now()).total_seconds() #type: ignore
            #     print(f"Sleeping for {seconds_to_sleep}")
            #     await asyncio.sleep(seconds_to_sleep)
            # else:
            await asyncio.sleep(60 * config.action_deadline)


            if gamestate.is_game_over(): # in case immediate actions ended the game
                break

            if not gamestate.is_valid_nightkill(nightkill_choice):
                nightkill_choice = gamestate.get_random_town()

            await resolve_day_or_night_end_actions(elimination_or_nightkill=nightkill_choice, gamestate=gamestate, was_tie=False, is_day=False)

    await announce_game_end(mafia_list=mafia_list)

