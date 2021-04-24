import pytest

from server import *
from client import *
from stroll import *

import subprocess as sp

subscriptions = ['gym', 'restaurant', 'school']

def test_setup():
	command = 'python3 server.py setup'
	for sub in subscriptions:
		command += ' -S ' + sub
	
	try:
		retcode = sp.call(command, shell=True)
		if retcode != 0:
			print("Child was terminated by signal", -retcode, file=sys.stderr)
		else:
			print("Child returned", retcode, file=sys.stderr)
	except OSError as e:
		print("Execution failed:", e, file=sys.stderr)
		
def test_get_pk():
	# start server
	_ = sp.Popen(['python3 server.py', 'run'])
	
	try:
		retcode = sp.call('python3 client.py get-pk', shell=True)
		if retcode != 0:
			print("Child was terminated by signal", -retcode, file=sys.stderr)
		else:
			print("Child returned", retcode, file=sys.stderr)
	except OSError as e:
		print("Execution failed:", e, file=sys.stderr)
	
