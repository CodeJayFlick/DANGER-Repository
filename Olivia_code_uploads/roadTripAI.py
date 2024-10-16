# List of states available for the road trip
states = ["California", "Nevada", "Oregon", "Arizona", "Utah", "Colorado", "New Mexico", "Idaho", "Montana", "Wyoming"]

# Track visited states and the number of travels
visited_states = []
max_travels = 10

# Function to display available states
def show_states():
    print("\nAvailable states to visit:")
    for state in states:
        print(f"- {state}")

# Main road trip function
def road_trip():
    travels = 0
    
    print("Welcome to the Road Trip Planner!")
    while True:
        print("\nWhat would you like to do?")
        print("1. Start Trip")
        print("2. Continue Trip")
        print("3. End Trip")
        choice = input("Enter your choice (1, 2, or 3): ").strip()
        
        if choice == "1":  # Start the trip
            if travels == 0:
                print("\nLet's start your trip!")
                show_states()
                start_state = input("\nEnter the state you want to start in: ").strip()
                if start_state in states:
                    visited_states.append(start_state)
                    travels += 1
                    print(f"\nYou have started your trip in {start_state}.")
                else:
                    print("Invalid state. Please try again.")
            else:
                print("You have already started the trip. Use option 2 to continue.")
        
        elif choice == "2":  # Continue the trip
            if travels > 0:
                if travels < max_travels:
                    show_states()
                    next_state = input("\nEnter the state you want to visit next: ").strip()
                    if next_state in states:
                        visited_states.append(next_state)
                        travels += 1
                        print(f"\nYou have traveled to {next_state}.")
                    else:
                        print("Invalid state. Please try again.")
                else:
                    print("You have reached the maximum travel limit. End the trip.")
                    break
            else:
                print("You need to start the trip first. Use option 1 to begin.")
        
        elif choice == "3":  # End the trip
            print("\nEnding your trip...")
            break
        
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
    
    # Trip summary
    if visited_states:
        print("\nTrip Summary:")
        print(f"Total states visited: {len(visited_states)}")
        print("States visited:")
        for state in visited_states:
            print(f"- {state}")
    else:
        print("\nYou didn't visit any states.")

# Run the road trip planner
road_trip()
