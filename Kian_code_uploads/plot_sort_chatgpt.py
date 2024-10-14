import matplotlib.pyplot as plt
import numpy as np
import time

# Function to visualize the array as a bar chart
def visualize(data, title, pause_time=0.1):
    plt.clf()  # Clear the previous plot
    plt.bar(range(len(data)), data, color='blue')
    plt.title(title)
    plt.xlabel('Index')
    plt.ylabel('Value')
    plt.draw()  # Update the plot
    plt.pause(pause_time)  # Pause to allow the plot to render

# Quicksort algorithm with visualization
def quicksort_visual(data, low, high):
    if low < high:
        pi = partition_visual(data, low, high)
        quicksort_visual(data, low, pi - 1)  # Left partition
        quicksort_visual(data, pi + 1, high)  # Right partition

# Partition function with visualization
def partition_visual(data, low, high):
    pivot = data[high]  # Pivot element
    i = low - 1  # Index of smaller element

    for j in range(low, high):
        if data[j] < pivot:
            i += 1
            data[i], data[j] = data[j], data[i]  # Swap
            visualize(data, f'Pivot: {pivot} | Swapping: {data[i]} and {data[j]}')  # Visualize each swap

    data[i + 1], data[high] = data[high], data[i + 1]  # Swap pivot to the correct position
    visualize(data, f'Pivot: {pivot} moved to correct position')  # Visualize pivot placement

    return i + 1

# Main function to run the visualization
def run_visual_quicksort(data):
    plt.figure(figsize=(10, 6))
    plt.ion()  # Enable interactive mode
    visualize(data, 'Initial array', 1)  # Visualize the initial array
    quicksort_visual(data, 0, len(data) - 1)  # Sort with visualization
    visualize(data, 'Sorted array', 2)  # Visualize the final sorted array
    plt.ioff()  # Disable interactive mode
    plt.show()  # Show the final result

# Example usage
if __name__ == "__main__":
    data = np.random.randint(1, 100, size=20)  # Generate a random array
    run_visual_quicksort(data)

