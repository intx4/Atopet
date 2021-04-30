import os
import time
users = ['user1', 'user2', 'user3']
subs = {"user1": "gym",
        "user2": "mall",
        "user3": "restaurant"}
creds = {"user1": "anon1.cred",
         "user2": "anon2.cred",
         "user3": "anon3.cred"}
cell_ids = range(1, 101)
REP = 10
j = 1
for cell_id in range(1,2):
	for user in users:
		for _ in range(0,2):
			print("MAKING REQUEST ", j)
			command = f'python3 client.py grid {cell_id} -c {creds[user]} -T {subs[user]} -t'
			os.system(command)
			time.sleep(5)
			j = j + 1
