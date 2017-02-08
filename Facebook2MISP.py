#!/usr/bin/python2 -O
#  -*- coding:utf-8 -*-

"""
	Retrieve events from Facebook Threat Exchange and push them to MISP

	Author: David DURVAUX
	Copyright: EC DIGIT CSIRC - February 2017

	POC version (actually not yet a poc, too much missing code)!! 

	To run, set TX_APP_ID and TX_APP_SECRET

	TODO:
		- credential management
		- fine control over MISP event creation
		- switch to Python 3.4 (see warnings)
"""
import os
import sys
import json
import time
import ast
import urllib
import requests

# Import MISP API
from pymisp import PyMISP


def retrieveMalwareAnalysesLast24h():
	app_id = os.environ['TX_APP_ID']
	app_secret = os.environ['TX_APP_SECRET']
	end_time = int(time.time()) # NOW
	start_time = end_time - (24 * 3600) # NOW - 24h
	
	query_params = urllib.urlencode({
    	'access_token' : app_id + '|' + app_secret,
    	'since' : start_time,
    	'until' : end_time
    	})
	
	r = requests.get('https://graph.facebook.com/v2.8/malware_analyses?' + query_params)
	
	print json.dumps(ast.literal_eval(r.text), sort_keys=True,indent=4,separators=(',', ': '))


"""
    Main function
"""
def main():
	# Validate if credential for Facebook are available
	if 'TX_APP_ID' not in os.environ or 'TX_APP_SECRET' not in os.environ:
		print("Facebook Threat Exchange credential unavailable :'(.")
		sys.exit(-1)

	# Retrieve event from Facebook
	retrieveMalwareAnalysesLast24h() #TEST!!

	# All done ;)
	return


"""
   Call main function
"""
if __name__ == "__main__":
    
    # Create an instance of the Analysis class (called "base") and run main 
    main()

# That's all folks ;)