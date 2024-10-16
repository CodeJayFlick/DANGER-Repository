# Constants
speed_of_light = 3.0e8  # Speed of light in meters per second
planck_constant = 6.626e-34  # Planck's constant in Joule seconds

# Input: frequency of the wave
frequency = float(input("Enter the frequency of the wave (in Hz): "))

# Calculate Wavelength
wavelength = speed_of_light / frequency

# Calculate Energy
energy = planck_constant * frequency

# Output Results
print(f"\nResults:")
print(f"Wavelength: {wavelength} meters")
print(f"Energy: {energy} Joules")