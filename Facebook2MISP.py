#!/usr/bin/python2 -O
#  -*- coding:utf-8 -*-

"""
	Retrieve events from Facebook Threat Exchange and push them to MISP

	Author: David DURVAUX
	Copyright: EC DIGIT CSIRC - February 2017

	POC version (actually not yet a poc, too much missing code)!! 

	To run, set TX_APP_ID and TX_APP_SECRET

	Note - Python API dropped - easier to use web queries
		API well described here: 
		https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-indicators/v2.8

	TODO:
		- credential management
		- fine control over MISP event creation
		- switch to Python 3.4 (see warnings)
		- create a class for Facebook
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

class FacebookTE():
	app_id = None
	app_secret = None

	def __init__(self, app_id, app_secret):
		self.app_id = app_id
		self.app_secret = app_secret



	def retrieveMalwareAnalysesLastNDays(self, numbdays):
		"""
			Retrieve the list of malware analysis published
			for the last numbdays.
		"""
		end_time = int(time.time()) # NOW
		start_time = end_time - numbdays * (24 * 3600)
		
		query_params = urllib.urlencode({
    		'access_token' : self.app_id + '|' + self.app_secret,
    		'since' : start_time,
    		'until' : end_time
    		})
		
		r = requests.get('https://graph.facebook.com/v2.8/malware_analyses?' + query_params)
		
		print json.dumps(ast.literal_eval(r.text), sort_keys=True,indent=4,separators=(',', ': '))
	
	
	def retrieveThreatIndicatorsLastNDays(self, numbdays):
		"""
			Retrieve the list of published indicators
			for the last numbdays.
		"""
		end_time = int(time.time()) # NOW
		start_time = end_time - numbdays * (24 * 3600) # NOW - 24h
	
		query_params = urllib.urlencode({
    		'access_token' : self.app_id + '|' + self.app_secret,
    		'since' : start_time,
    		'until' : end_time
    		})
		
		r = requests.get('https://graph.facebook.com/v2.8/threat_indicators?' + query_params)
		
		print json.dumps(ast.literal_eval(r.text), sort_keys=True,indent=4,separators=(',', ': '))	

	def retrieveEvent(self, eventid):
		print("NOT IMPLEMENTED")
		return None


"""
    Main function
"""
def main():
	# Validate if credential for Facebook are available
	if 'TX_APP_ID' not in os.environ or 'TX_APP_SECRET' not in os.environ:
		print("Facebook Threat Exchange credential unavailable :'(.")
		sys.exit(-1)

	# Retrieve event from Facebook
	fb = FacebookTE(os.environ['TX_APP_ID'], os.environ['TX_APP_SECRET'])
	fb.retrieveThreatIndicatorsLastNDays(1) # TEST

	# TODO - for each new publisehd Indicators, retrieve full object
	# then pushed to MISP

	# All done ;)
	return


"""
   Call main function
"""
if __name__ == "__main__":
    
    # Create an instance of the Analysis class (called "base") and run main 
    main()

# That's all folks ;)