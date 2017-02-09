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
	-----
		- fine control over MISP event creation
		- switch to Python 3.4 (see warnings)
		- add command line parameters (to control behaviour, pass auth to FB...)
		- improve handler for params (function to generate structure) -> code duplication!!
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

# --------------------------------------------------------------------------- #

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
		
		query_params = {
    		'since' : start_time,
    		'until' : end_time
    	}
		
		return self.__query_threat_exchange__("malware_analyses", query_params)
	
	
	def retrieveThreatIndicatorsLastNDays(self, numbdays):
		"""
			Retrieve the list of published indicators
			for the last numbdays.
		"""	
		end_time = int(time.time()) # NOW
		start_time = end_time - numbdays * (24 * 3600) # NOW - 24h
	
		query_params = {
    		'since' : start_time,
    		'until' : end_time
    	}
		
		return self.__query_threat_exchange__("threat_indicators", query_params)


	def retrieveThreatDescriptorsLastNDays(self, numbdays):
		"""
			Retrieve the list of published indicators
			for the last numbdays.
		"""
		end_time = int(time.time()) # NOW
		start_time = end_time - numbdays * (24 * 3600) # NOW - 24h
	
		query_params = {
    		'since' : start_time,
    		'until' : end_time
    	}
		
		return self.__query_threat_exchange__("threat_descriptors", query_params)


	def retrieveEvent(self, eventid):
		print("NOT IMPLEMENTED")
		return None


	def __query_threat_exchange__(self, query_type, params={}):
		"""
			Generic function to query Facebook with URL format:
			'https://graph.facebook.com/v2.8/<query_type>?' + query_params

			checkout: 
				https://developers.facebook.com/docs/threat-exchange/reference/apis/v2.8

			params = hashtable containing all query option EXCEPT auth which will be added
			         by this function
		"""
		try:
			params['access_token'] = self.app_id + '|' + self.app_secret
			uparams = urllib.urlencode(params)

			uri = 'https://graph.facebook.com/v2.8/%s?' % query_type
			request = requests.get(uri + uparams)
			return json.dumps(ast.literal_eval(request.text), sort_keys=True,indent=4,separators=(',', ': '))	
		except Exception as e:
			print("Impossible to query %s" % query_type)
			print(e)
		return None

# --------------------------------------------------------------------------- #

class MISP():
	api = ""
	url = ""
	misp = 
	sslCheck = False # Not recommended
	debug = True     # Enable debug mode

	type_map = {
		"URI" : "url",
	}

	def __init__(self, url, api):
		self.url = url
		self.api = api
		self.misp = pymisp.api.PyMISP(self.url, self.key, ssl=self.sslCheck, out_type=’json’, debug=self.debug, proxies=None, cert=None)
		return


	def convertTEtoMISP(self, teevent):
		print("NOT IMPLEMENTED")
		return


	def createEvent(self, event={}):
		jevent = json.dumps(event)
		print("NOT IMPLEMENTED")
		# create the event
		return

# --------------------------------------------------------------------------- #

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
	print fb.retrieveThreatDescriptorsLastNDays(1) # TEST

	# TODO - for each new publisehd Indicators, retrieve full object
	# then pushed to MISP

	# All done ;)
	return

# --------------------------------------------------------------------------- #

"""
   Call main function
"""
if __name__ == "__main__":
    
    # Create an instance of the Analysis class (called "base") and run main 
    main()

# That's all folks ;)