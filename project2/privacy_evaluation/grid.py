import bisect
import random as r

## Grid parameters
# Top left corner of the area
MAP_LAT = 46.5
MAP_LON = 6.55

# Total area size
MAP_SIZE_LAT = 0.07
MAP_SIZE_LON = 0.10

# Number of cells
CELL_NUM_LAT = 10
CELL_NUM_LON = 10

# Grid lines
GRID_LAT_POINTS = [MAP_LAT + i * (MAP_SIZE_LAT / CELL_NUM_LAT)
                   for i in range(1, CELL_NUM_LAT + 1)]
GRID_LON_POINTS = [MAP_LON + i * (MAP_SIZE_LON / CELL_NUM_LON)
                   for i in range(1, CELL_NUM_LON + 1)]


def location_to_cell_id(lat, lon):
    """Get the grid cell ID for a given latitude and longitude."""
    if not (MAP_LAT <= lat < MAP_LAT + MAP_SIZE_LAT) or not (
        MAP_LON <= lon < MAP_LON + MAP_SIZE_LON
    ):
        #raise ValueError("Out of area range.")
        return -1
    i = bisect.bisect(GRID_LAT_POINTS, lat)
    j = bisect.bisect(GRID_LON_POINTS, lon)
    return i * CELL_NUM_LAT + j + 1

""" mimics defense mechanism via randomization """
def get_rand_loc_in_neigh(cell_id):
    neighs = {}
    neighs["left"] = False
    neighs["top"] = False
    neighs["bottom"] = False
    neighs["right"] = False
    
    if (cell_id - 1) % CELL_NUM_LON != 0:
        if cell_id % CELL_NUM_LON >= 5:
            neighs["left"] = True
    if (cell_id - CELL_NUM_LAT) > 0:
        if cell_id // CELL_NUM_LAT >= 5:
            neighs["top"] = True
    if (cell_id + CELL_NUM_LAT) <= (CELL_NUM_LAT * CELL_NUM_LON):
        if cell_id // CELL_NUM_LAT < 5:
            neighs["bottom"] = True
    if (cell_id + 1) % CELL_NUM_LON != 1:
        if cell_id % CELL_NUM_LON < 5:
            neighs["right"] = True
    
    eligibles = []
    for cell in neighs.items():
        if cell[1] == True:
            eligibles.append(cell[0])
    
    rand = r.randint(0, len(eligibles)-1)
    choice = eligibles[rand]
    
    if choice == "this":
        n = cell_id
    if choice == "left":
        n = cell_id - 1
    if choice == "top":
        n = cell_id - CELL_NUM_LON
    if choice == "bottom":
        n = cell_id + CELL_NUM_LON
    if choice == "right":
        n = cell_id + 1

    #print(f"Choice:{n} from {cell_id}")
    n = n - 1  # as index
    extremes_lat = []
    extremes_lon = []
    if (n // CELL_NUM_LAT) == 0:
        extremes_lat.append(MAP_LAT)
    else:
        extremes_lat.append(GRID_LAT_POINTS[(n // CELL_NUM_LAT) - 1])
    extremes_lat.append(GRID_LAT_POINTS[(n // CELL_NUM_LAT)])
    
    if (n % CELL_NUM_LON) == 0:
        extremes_lon.append(MAP_LON)
    else:
        extremes_lon.append(GRID_LON_POINTS[(n % CELL_NUM_LON) - 1])
    extremes_lon.append(GRID_LON_POINTS[(n % CELL_NUM_LON)])
    
    #print(extremes_lat)
    lat = r.uniform(extremes_lat[0], extremes_lat[1])
    #print(GRID_LAT_POINTS)
    #print(extremes_lon)
    lon = r.uniform(extremes_lon[0], extremes_lon[1])
    #print(GRID_LON_POINTS)
    return (lat, lon)


""" TEST
t = get_rand_loc_in_neigh(1)
print(location_to_cell_id(t[0],t[1]))
t = get_rand_loc_in_neigh(10)
print(location_to_cell_id(t[0],t[1]))
t = get_rand_loc_in_neigh(56)
print(location_to_cell_id(t[0],t[1]))
t = get_rand_loc_in_neigh(91)
print(location_to_cell_id(t[0],t[1]))
t = get_rand_loc_in_neigh(100)
print(location_to_cell_id(t[0],t[1]))
"""