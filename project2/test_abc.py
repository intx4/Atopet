import jsonpickle
import pytest
from stroll import *
from credential import gen_rand_point

""" Test suite for ensuring the correctness of the ABC protocol """

def test_full_complete_run():
	""" Simulates a correct run of the ABC protocol """
	server = Server()
	client = Client()
	
	#server setup
	server_private_key, server_public_key = server.generate_ca(['sushi', 'mall', 'shoes', 'username'])
	
	#client setup
	client_name = 'John'
	client_subscriptions = ['mall', 'sushi']
	client_message = (f"{23445},{6.57890}").encode("utf-8")
	
	#create client issue request
	request, state = client.prepare_registration(server_public_key, client_name, client_subscriptions)
	
	#'send' issue request to server and get response
	sigma_obfuscated = server.process_registration(server_private_key, server_public_key, request, client_name,
												   client_subscriptions)
	
	#process server response and create credentials
	credentials = client.process_registration_response(server_public_key, sigma_obfuscated, state)
	
	#simulate showing protocol
	client_service_request = client.sign_request(server_public_key, credentials, client_message, client_subscriptions)
	assert server.check_request_signature(server_public_key, client_message, client_subscriptions, client_service_request)

def test_registering_invalid_attributes():
	""" Simulates a wrong run of the ABC protocol: client tries to subscribe with an invalid attribute """
	server = Server()
	client = Client()
	
	# server setup
	server_private_key, server_public_key = server.generate_ca(['sushi', 'mall', 'shoes', 'username'])
	
	# client setup
	client_name = 'John'
	client_subscriptions = ['mall', 'invalid_attribute']
	client_message = (f"{23445},{6.57890}").encode("utf-8")
	
	# create client issue request
	request, state = client.prepare_registration(server_public_key, client_name, client_subscriptions)
	
	with pytest.raises(Exception):
		# server raises an exception because one attribute is not valid
		server.process_registration(server_private_key, server_public_key, request, client_name,client_subscriptions)

def test_requesting_service_not_subscribed():
	""" Simulates a wrong run of the ABC protocol: client tries to ask for a service he did not subscribe to """
	server = Server()
	client = Client()
	
	# server setup
	server_private_key, server_public_key = server.generate_ca(['sushi', 'mall', 'shoes', 'username'])
	
	# client setup
	client_name = 'John'
	client_subscriptions = ['mall', 'sushi']
	client_request_subscriptions = ['shoes'] #service client did not subscribe to
	client_message = (f"{23445},{6.57890}").encode("utf-8")
	
	# create client issue request
	request, state = client.prepare_registration(server_public_key, client_name, client_subscriptions)
	
	# 'send' issue request to server and get response
	sigma_obfuscated = server.process_registration(server_private_key, server_public_key, request, client_name,
	                                               client_subscriptions)
	
	# process server response and create credentials
	credentials = client.process_registration_response(server_public_key, sigma_obfuscated, state)
	
	client_service_request = client.sign_request(server_public_key, credentials, client_message,
												 client_request_subscriptions)
	
	#the disclosure proof won't be valid
	assert not server.check_request_signature(server_public_key, client_message, client_request_subscriptions,
										  	client_service_request)

def test_invalid_signature_on_message():
	""" Simulates a wrong run of the ABC protocol: client presents a signature for a different message/location """
	server = Server()
	client = Client()
	
	# server setup
	server_private_key, server_public_key = server.generate_ca(['sushi', 'mall', 'shoes', 'username'])
	
	# client setup
	client_name = 'John'
	client_subscriptions = ['mall', 'sushi']
	client_message = (f"{23445},{6.57890}").encode("utf-8")
	
	# create client issue request
	request, state = client.prepare_registration(server_public_key, client_name, client_subscriptions)
	
	# 'send' issue request to server and get response
	sigma_obfuscated = server.process_registration(server_private_key, server_public_key, request, client_name,
	                                               client_subscriptions)
	
	# process server response and create credentials
	credentials = client.process_registration_response(server_public_key, sigma_obfuscated, state)
	
	client_service_request = client.sign_request(server_public_key, credentials, client_message,
	                                             client_subscriptions)
	
	# the disclosure proof won't be valid
	assert not server.check_request_signature(server_public_key, b'a_different_location', client_subscriptions,
	                                          client_service_request)

def test_invalid_user_commitment():
	""" Simulates a wrong run of the ABC protocol: client present an invalid proof for the commitment at issuing time """
	server = Server()
	client = Client()
	
	# server setup
	server_private_key, server_public_key = server.generate_ca(['sushi', 'mall', 'shoes', 'username'])
	
	# client setup
	client_name = 'John'
	client_subscriptions = ['mall', 'sushi']
	
	# create client issue request
	request, state = client.prepare_registration(server_public_key, client_name, client_subscriptions)
	
	#modify the commitment in the Pedersen Proof
	request_d: IssueRequest = jsonpickle.decode(request.decode(), classes=IssueRequest)
	request_d.proof.commitment = gen_rand_point()
	request = jsonpickle.encode(request_d).encode()
	
	# server process issue request
	sigma_obfuscated = server.process_registration(server_private_key, server_public_key, request, client_name,
												   client_subscriptions)
	with pytest.raises(Exception):
		#server will send a not valid signature as result for an invalid NIZKP
		client.process_registration_response(server_public_key, sigma_obfuscated, state)
