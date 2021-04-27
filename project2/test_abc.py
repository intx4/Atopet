import jsonpickle
import pytest
from stroll import *
from credential import gen_rand_point

def test_full_complete_run():
	server = Server()
	client = Client()
	client_name = 'John'
	client_subscriptions = ['mall', 'sushi']
	client_message = (f"{23445},{6.57890}").encode("utf-8")
	server_private_key, server_public_key = server.generate_ca(['sushi', 'mall', 'shoes', 'username'])
	request, state = client.prepare_registration(server_public_key, client_name, client_subscriptions)
	sigma_obfuscated = server.process_registration(server_private_key, server_public_key, request, client_name,
												   client_subscriptions)
	credentials = client.process_registration_response(server_public_key, sigma_obfuscated, state)
	client_service_request = client.sign_request(server_public_key, credentials, client_message, client_subscriptions)
	assert server.check_request_signature(server_public_key, client_message, client_subscriptions, client_service_request)

def test_registering_invalid_attributes():
	server = Server()
	client = Client()
	client_name = 'John'
	client_subscriptions = ['mall', 'shsafd']
	server_private_key, server_public_key = server.generate_ca(['sushi', 'mall', 'shoes', 'username'])
	request, state = client.prepare_registration(server_public_key, client_name, client_subscriptions)

	with pytest.raises(Exception):
		server.process_registration(server_private_key, server_public_key, request, client_name,client_subscriptions)

def test_requesting_service_not_subscribed():
	server = Server()
	client = Client()
	client_name = 'John'
	client_subscriptions = ['mall', 'sushi']
	client_request_subscriptions = ['shoes']
	client_message = (f"{23445},{6.57890}").encode("utf-8")
	server_private_key, server_public_key = server.generate_ca(['sushi', 'mall', 'shoes', 'username'])
	request, state = client.prepare_registration(server_public_key, client_name, client_subscriptions)
	sigma_obfuscated = server.process_registration(server_private_key, server_public_key, request, client_name,
												client_subscriptions)

	credentials = client.process_registration_response(server_public_key, sigma_obfuscated, state)
	client_service_request = client.sign_request(server_public_key, credentials, client_message,
												 client_request_subscriptions)
	assert not server.check_request_signature(server_public_key, client_message, client_request_subscriptions,
										  	client_service_request)

def test_invalid_user_commitment():
	server = Server()
	client = Client()
	client_name = 'John'
	client_subscriptions = ['mall', 'sushi']
	server_private_key, server_public_key = server.generate_ca(['sushi', 'mall', 'shoes', 'username'])
	request, state = client.prepare_registration(server_public_key, client_name, client_subscriptions)
	request: IssueRequest = jsonpickle.decode(request.decode(), classes=IssueRequest)
	request.proof.commitment = gen_rand_point()
	request = jsonpickle.encode(request).encode()
	sigma_obfuscated = server.process_registration(server_private_key, server_public_key, request, client_name,
												   client_subscriptions)
	with pytest.raises(Exception):
		client.process_registration_response(server_public_key, sigma_obfuscated, state)
