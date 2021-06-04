import time
import csv
import os

from stroll import *
from credential import *

file = os.getcwd() + '/performance_analysis/'
REP = 20
subscription_num = [5, 10, 15, 20, 30, 50, 75, 100, 150, 200]

def test_key_gen():
	server = Server()

	for sub_num in subscription_num:
		subscriptions = []
		for i in range(0, sub_num):
			sub = "Sub_"+str(i)
			subscriptions.append(sub)
		for _ in range(0, REP):
			# server setup
			tic = time.time()
			server_private_key, server_public_key = server.generate_ca(subscriptions)
			toc = time.time()
			elapsed = toc - tic
			with open(file+'keygen_runtime.csv', 'a+') as csvfile:
				writer = csv.writer(csvfile)
				writer.writerow([sub_num, elapsed])
				
			key_bytes = len(server_public_key)
			with open(file+'keygen_data.csv', 'a+') as csvfile:
				writer = csv.writer(csvfile)
				writer.writerow([sub_num, key_bytes])

def test_issuance_req():
	server = Server()
	client = Client()
	for sub_num in subscription_num:
		subscriptions = []
		for i in range(0, sub_num):
			sub = "Sub_"+str(i)
			subscriptions.append(sub)
		subscriptions.append('username')
		for _ in range(0, REP):
			# server setup
			server_private_key, server_public_key = server.generate_ca(subscriptions)
	
			# client setup
			client_name = 'John'
			client_subscriptions = subscriptions[:-1]
				
			tic = time.time()
			# create client issue request
			request, state = client.prepare_registration(server_public_key, client_name, client_subscriptions)
				
			# 'send' issue request to server and get response
			sigma_obfuscated = server.process_registration(server_private_key, server_public_key, request, client_name,
	                                               client_subscriptions)
	
			# process server response and create credentials
			credentials = client.process_registration_response(server_public_key, sigma_obfuscated, state)
				
			toc = time.time()
			elapsed = toc - tic
			
			with open(file + 'issuance_runtime.csv', 'a+') as csvfile:
				writer = csv.writer(csvfile)
				writer.writerow([sub_num, elapsed])
				
			with open(file + 'issuance_data.csv', 'a+') as csvfile:
				writer = csv.writer(csvfile)
				#num_sub, bytes_out_client, bytes_out_server
				writer.writerow([sub_num, len(request), len(sigma_obfuscated)])

def test_showing():
	server = Server()
	client = Client()
	for sub_num in subscription_num:
		subscriptions = []
		for i in range(0, sub_num):
			sub = "Sub_" + str(i)
			subscriptions.append(sub)
		subscriptions.append('username')
		for _ in range(0, REP):
			# server setup
			server_private_key, server_public_key = server.generate_ca(subscriptions)
			
			# client setup
			client_name = 'John'
			client_subscriptions = subscriptions[:-1]
			client_message = b'a_message'
			
			
			# create client issue request
			request, state = client.prepare_registration(server_public_key, client_name, client_subscriptions)
			
			# 'send' issue request to server and get response
			sigma_obfuscated = server.process_registration(server_private_key, server_public_key, request, client_name,
			                                               client_subscriptions)
			
			# process server response and create credentials
			credentials = client.process_registration_response(server_public_key, sigma_obfuscated, state)
			
			tic = time.time()
			client_service_request = client.sign_request(server_public_key, credentials, client_message,
			                                             client_subscriptions)
			toc = time.time()
			elapsed = toc - tic
			client_bytes_out = len(client_service_request)
			with open(file + 'showing_runtime.csv', 'a+') as csvfile:
				writer = csv.writer(csvfile)
				writer.writerow([sub_num, elapsed])
			
			with open(file + 'showing_data.csv', 'a+') as csvfile:
				writer = csv.writer(csvfile)
				# num_sub, bytes_out_client, bytes_out_server
				writer.writerow([sub_num,client_bytes_out])
				
def test_verification():
	server = Server()
	client = Client()
	for sub_num in subscription_num:
		subscriptions = []
		for i in range(0, sub_num):
			sub = "Sub_" + str(i)
			subscriptions.append(sub)
		subscriptions.append('username')
		for _ in range(0, REP):
			# server setup
			server_private_key, server_public_key = server.generate_ca(subscriptions)
			
			# client setup
			client_name = 'John'
			client_subscriptions = subscriptions[:-1]
			client_message = b'a_message'
			
			# create client issue request
			request, state = client.prepare_registration(server_public_key, client_name, client_subscriptions)
			
			# 'send' issue request to server and get response
			sigma_obfuscated = server.process_registration(server_private_key, server_public_key, request, client_name,
			                                               client_subscriptions)
			
			# process server response and create credentials
			credentials = client.process_registration_response(server_public_key, sigma_obfuscated, state)
			
			
			client_service_request = client.sign_request(server_public_key, credentials, client_message,
			                                             client_subscriptions)
			tic = time.time()
			assert server.check_request_signature(server_public_key, client_message, client_subscriptions, client_service_request)
			toc = time.time()
			elapsed = toc - tic
			
			with open(file + 'verification_runtime.csv', 'a+') as csvfile:
				writer = csv.writer(csvfile)
				writer.writerow([sub_num, elapsed])
			