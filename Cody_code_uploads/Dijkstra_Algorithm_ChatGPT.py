import heapq


def dijkstra(graph, start):
    # Priority queue to hold (distance, vertex)
    priority_queue = []

    # Distances dictionary to hold the shortest distance from start to each vertex
    distances = {vertex: float('infinity') for vertex in graph}
    distances[start] = 0
    heapq.heappush(priority_queue, (0, start))

    while priority_queue:
        current_distance, current_vertex = heapq.heappop(priority_queue)

        # If the current distance is greater than the recorded distance, skip processing
        if current_distance > distances[current_vertex]:
            continue

        for neighbor, weight in graph[current_vertex].items():
            distance = current_distance + weight

            # Only consider this new path if it's better
            if distance < distances[neighbor]:
                distances[neighbor] = distance
                heapq.heappush(priority_queue, (distance, neighbor))

    return distances


# Example usage
if __name__ == "__main__":
    # Define the graph as a dictionary
    graph = {
        'A': {'B': 1, 'C': 4},
        'B': {'A': 1, 'C': 2, 'D': 5},
        'C': {'A': 4, 'B': 2, 'D': 1},
        'D': {'B': 5, 'C': 1}
    }

    start_vertex = 'A'
    shortest_paths = dijkstra(graph, start_vertex)

    print(f"Shortest paths from {start_vertex}: {shortest_paths}")