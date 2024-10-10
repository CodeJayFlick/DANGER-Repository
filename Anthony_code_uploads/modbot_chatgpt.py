import random
import discord
from discord.ext import commands

intents = discord.Intents.default()
intents.members = True

bot = commands.Bot(command_prefix='!', intents=intents)

# Game Data
roles = ["Mafia", "Mafia", "Doctor", "Cop", "Townsperson", "Townsperson", "Townsperson"]
players = {}
votes = {}
day_phase = True
alive_players = []

# Role Assignment
def assign_roles(members):
    random.shuffle(roles)
    for i, member in enumerate(members):
        players[member] = {
            'role': roles[i],
            'alive': True
        }
        alive_players.append(member)

# Helper function to send role details to players
async def send_roles():
    for member, info in players.items():
        await member.send(f"Your role is: {info['role']}")

# Start Game Command
@bot.command(name='start_game')
async def start_game(ctx):
    if len(ctx.guild.members) - 1 != len(roles):
        await ctx.send("Wrong number of players. You need exactly 7 players to start!")
        return
    members = [member for member in ctx.guild.members if not member.bot]
    assign_roles(members)
    await send_roles()
    await ctx.send("Roles have been assigned! The game has begun!")

# Vote Command for Day Phase
@bot.command(name='vote')
async def vote(ctx, target: discord.Member):
    if not day_phase:
        await ctx.send("You can only vote during the day phase.")
        return

    if target not in alive_players:
        await ctx.send(f"{target.display_name} is already dead!")
        return

    votes[ctx.author] = target
    await ctx.send(f"{ctx.author.display_name} has voted for {target.display_name}")

    if len(votes) == len(alive_players):  # If all alive players have voted
        await tally_votes(ctx)

# Tally Votes and Determine Lynch
async def tally_votes(ctx):
    vote_count = {}
    for voter, target in votes.items():
        if target in vote_count:
            vote_count[target] += 1
        else:
            vote_count[target] = 1

    max_votes = max(vote_count.values())
    lynched = [target for target, count in vote_count.items() if count == max_votes]

    if len(lynched) == 1:
        await ctx.send(f"{lynched[0].display_name} has been lynched!")
        players[lynched[0]]['alive'] = False
        alive_players.remove(lynched[0])
    else:
        await ctx.send("It's a tie! No one is lynched.")

    # Reset votes
    votes.clear()
    await switch_to_night(ctx)

# Switch to Night Phase
async def switch_to_night(ctx):
    global day_phase
    day_phase = False
    await ctx.send("Night falls. Mafia, Doctor, and Cop, please submit your actions in private messages.")
    
    # Simulate mafia, doctor, and cop actions
    await process_night_actions(ctx)
    await switch_to_day(ctx)

# Process Night Actions
async def process_night_actions(ctx):
    # These would be handled by receiving DM commands from Mafia, Doctor, and Cop.
    mafia_target = None
    doctor_save = None
    cop_investigation = None

    # Dummy: Random actions for the night
    if any(player['role'] == 'Mafia' for player in alive_players):
        mafia_target = random.choice([p for p in alive_players if players[p]['role'] != 'Mafia'])
    
    if any(player['role'] == 'Doctor' for player in alive_players):
        doctor_save = random.choice(alive_players)
    
    if any(player['role'] == 'Cop' for player in alive_players):
        cop_investigation = random.choice(alive_players)
        cop_role = players[cop_investigation]['role']
        await ctx.send(f"The Cop investigates {cop_investigation.display_name} and discovers they are a {cop_role}")

    if mafia_target == doctor_save:
        await ctx.send(f"The Doctor saved {mafia_target.display_name} during the night!")
    else:
        if mafia_target:
            await ctx.send(f"{mafia_target.display_name} was killed by the Mafia during the night!")
            players[mafia_target]['alive'] = False
            alive_players.remove(mafia_target)

# Switch to Day Phase
async def switch_to_day(ctx):
    global day_phase
    day_phase = True
    await ctx.send("Day breaks. Time to discuss and vote!")

# Check for Endgame
async def check_endgame(ctx):
    mafia_count = sum(1 for player in alive_players if players[player]['role'] == 'Mafia')
    town_count = len(alive_players) - mafia_count
    
    if mafia_count == 0:
        await ctx.send("The Town wins!")
        return True
    elif mafia_count >= town_count:
        await ctx.send("The Mafia wins!")
        return True
    return False

# Endgame Check After Each Phase
async def switch_to_day(ctx):
    global day_phase
    day_phase = True
    await ctx.send("Day breaks. Time to discuss and vote!")
    
    # Check for endgame conditions
    if await check_endgame(ctx):
        await ctx.send("The game is over!")
        return
