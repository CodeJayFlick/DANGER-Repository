import datetime

# Room details
rooms = {
    101: {"type": "Single", "price": 100, "booked": False},
    102: {"type": "Double", "price": 150, "booked": False},
    103: {"type": "Suite", "price": 250, "booked": False},
    104: {"type": "Single", "price": 100, "booked": False},
    105: {"type": "Double", "price": 150, "booked": False},
}

# Customer data
customers = {}


# Check room availability
def check_room_availability():
    print("Available Rooms:")
    for room_num, details in rooms.items():
        if not details['booked']:
            print(f"Room {room_num}: {details['type']} - ${details['price']} per night")


# Book a room
def book_room():
    name = input("Enter customer name: ")
    room_num = int(input("Enter room number to book: "))

    if rooms[room_num]["booked"]:
        print(f"Room {room_num} is already booked.")
        return

    check_in = input("Enter check-in date (YYYY-MM-DD): ")
    check_out = input("Enter check-out date (YYYY-MM-DD): ")

    # Convert strings to date objects
    check_in_date = datetime.datetime.strptime(check_in, "%Y-%m-%d").date()
    check_out_date = datetime.datetime.strptime(check_out, "%Y-%m-%d").date()

    # Calculate total nights
    total_nights = (check_out_date - check_in_date).days
    if total_nights <= 0:
        print("Check-out date must be after check-in date.")
        return

    total_cost = total_nights * rooms[room_num]["price"]
    print(f"Room {room_num} booked for {name} from {check_in} to {check_out}. Total cost: ${total_cost}")

    # Update room status
    rooms[room_num]["booked"] = True

    # Save customer details
    customers[room_num] = {
        "name": name,
        "check_in": check_in_date,
        "check_out": check_out_date,
        "total_cost": total_cost
    }


# Check-out process
def check_out_room():
    room_num = int(input("Enter room number for check-out: "))

    if room_num not in customers:
        print("No customer found in that room.")
        return

    # Retrieve customer data
    customer = customers.pop(room_num)
    print(f"Check-out completed for {customer['name']}. Total bill: ${customer['total_cost']}")

    # Mark room as available
    rooms[room_num]["booked"] = False


# View all booked rooms
def view_booked_rooms():
    print("Currently booked rooms:")
    for room_num, details in rooms.items():
        if details["booked"]:
            print(f"Room {room_num}: {customers[room_num]['name']} (Check-out: {customers[room_num]['check_out']})")


# Main menu
def main_menu():
    while True:
        print("\n--- Hotel Management System ---")
        print("1. Check Room Availability")
        print("2. Book a Room")
        print("3. Check-out")
        print("4. View Booked Rooms")
        print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            check_room_availability()
        elif choice == "2":
            book_room()
        elif choice == "3":
            check_out_room()
        elif choice == "4":
            view_booked_rooms()
        elif choice == "5":
            print("Exiting system.")
            break
        else:
            print("Invalid choice. Please try again.")


# Run the hotel management system
if __name__ == "__main__":
    main_menu()