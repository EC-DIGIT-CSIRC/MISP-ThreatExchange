#!/usr/bin/python2 -O
#  -*- coding:utf-8 -*-

"""
	Retrieve events from Facebook Threat Exchange and push them to MISP

	Author: David DURVAUX
	Copyright: EC DIGIT CSIRC - February 2017

	POC version (actually not yet a poc, too much missing code)!! 


	Note - Python API dropped - easier to use web queries
		API well described here: 
		https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-indicators/v2.8

	TODO:
	-----
		- fine control over MISP event creation
		- switch to Python 3.4 (see warnings)
		- add command line parameters (to control behaviour, pass auth to FB...)
		- remove all internal structure to JSON file

	Version: 0.000000001 :)
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

# Import configuration.py with API keys
import configuration

# --------------------------------------------------------------------------- #

class FacebookTE():
	app_id = None
	app_secret = None
	proxy = None


	def __init__(self, app_id, app_secret, proxy=None):
		self.app_id = app_id
		self.app_secret = app_secret
		self.proxy = proxy


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
		
		return json.loads(self.__query_threat_exchange__("malware_analyses", query_params))
	
	
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
		
		return json.loads(self.__query_threat_exchange__("threat_indicators", query_params))


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
		
		return json.loads(self.__query_threat_exchange__("threat_descriptors", query_params))


	def retrieveEvent(self, eventid, params={}):
		"""
			Sample Event:
			{
    			"added_on": "2017-02-09T14:26:57+0000",
    			"description": "IDS Detected Spam",
    			"id": "1234567890",
    			"indicator": {
        			"id": "1234567890",
        			"indicator": "11.22.33.44",
        			"type": "IP_ADDRESS"
    			},
    			"owner": {
        			"email": "foo\\u0040bar.com",
        			"id": "987654321",
        			"name": "FooBar ThreatExchange"
    			},
    			"privacy_type": "VISIBLE",
    			"raw_indicator": "11.22.33.44",
    			"share_level": "GREEN",
    			"status": "MALICIOUS",
    			"type": "IP_ADDRESS"
			}
		"""
		try:
			params['access_token'] = self.app_id + '|' + self.app_secret
			uparams = urllib.urlencode(params)

			uri = 'https://graph.facebook.com/%s?' % eventid
			request = requests.get(uri + uparams)
			return json.dumps(ast.literal_eval(request.text), sort_keys=True,indent=4,separators=(',', ': '))
		except Exception as e:
			print("Impossible to retrieve event %s" % eventid)
			print(e)
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
			request = requests.get(uri + uparams, proxies=self.proxy)
			return json.dumps(ast.literal_eval(request.text), sort_keys=True,indent=4,separators=(',', ': '))
		except Exception as e:
			print("Impossible to query %s" % query_type)
			print(e)
		return None

# --------------------------------------------------------------------------- #

class MISP():
	"""
		Handle manipulation of event into MISP

		TODO:
		    - use MISPEvent for creating MISP events
		         check https://www.circl.lu/assets/files/misp-training/luxembourg2017/4.1-pymisp.pdf
		    - use PyTaxonomies for Tags
	"""
	api = ""
	url = ""
	misp = ""
	proxies = None
	sslCheck = False # Not recommended
	debug = False     # Enable debug mode

	# ThreatExchange type -> MISP type
	# see IndicatorType object
	# 	https://developers.facebook.com/docs/threat-exchange/reference/apis/indicator-type/v2.8
	type_map = {
		"URI" : "url",
		"IP_ADDRESS" : "ip-dst", #Add mutliple attributes ip-dst and ip-src??
		"DOMAIN" : "domain",
	}

	# ThreatExchange -> MISP
	# None mean no mapping
	field_map = {
		"description" : "comment",
		"raw_indicator" : "value",
		"owner" : None,
		"status" : None
	}

	share_levels = {
		"WHITE" :
	        {
                "id": "1",
                "name": "tlp:white",
                "colour": "#ffffff",
                "exportable": True,
                "hide_tag": False
            }, 
		"GREEN" : 
			{
                "id": "2",
                "name": "tlp:green",
                "colour": "#13fd4b",
                "exportable": True,
                "hide_tag": False
            },
        "AMBER" :
            {
                "id": "3",
                "name": "tlp:amber",
                "colour": "#f8ba09",
                "exportable": True,
                "hide_tag": False
            }
	}


	def __init__(self, url, api, proxies=None):
		self.url = url
		self.api = api
		self.proxies = proxies
		self.misp = PyMISP(self.url, self.api, ssl=self.sslCheck, out_type='json', debug=self.debug, proxies=self.proxies, cert=None)
		return


	def convertTEtoMISP(self, teevent):
		"""
			convert a ThreatExchange entry to MISP entry
		"""
		# Skeleton of MISP event to publish (will be converted to JSON)
		mispevt = {
			"published": False,
			"info": "Import from Facebook ThreatExchange",
			"Attribute" : [],
			"Tag" : [],
		}

		# Add populated attributes
		attribute = {}
		for field in self.field_map.keys():
			if field in teevent.keys():
				if self.field_map[field] is not None:
					attribute[self.field_map[field]] = teevent[field].replace("\\", "") # not to brutal??

		# Add type of attribute
		if "type" in teevent.keys():
			if teevent["type"] in self.type_map.keys():
				attribute["type"] = self.type_map[teevent["type"]]
			else:
				print("WARNING: TYPE %s SHOULD BE ADDED TO MAPPING" % teevent["type"])


		# Add a category
		attribute["category"] = "Network activity"

		# Add new attriute to event
		mispevt["Attribute"].append(attribute)

		# Add sharing indicators (tags)
		if "share_level" in teevent.keys():
			if teevent["share_level"] in self.share_levels.keys():
				mispevt["Tag"].append(self.share_levels[teevent["share_level"]])
			else:
				print("WARNING: SHARING LEVEL %s SHOULD BE ADDED TO MAPPING" % teevent["share_level"])

		# all done :)
		return mispevt


	def createEvent(self, event={}):
		"""
			Create a new event in MISP using a hash table structure describing the event
		"""
		jevent = json.dumps(event, sort_keys=True,indent=4,separators=(',', ': '))
		print("DEBUG, event to add: %s" % jevent)
		misp_event = self.misp.add_event(jevent)
		return misp_event


	def saveMapping(self, mapfile="./mapping.json"):
		"""
			Save internal mapping definition
		"""
		mappings = {
			"Sharing" : self.share_levels,
			"Fields"  : self.field_map,
			"Type"    : self.type_map,
		}
		try:
			fd = open(mapfile, "w")
			json.dump(mappings, fd, sort_keys=True,indent=4,separators=(',', ': '))
			fd.close()
		except Exception as e:
			print("IMPOSSIBLE TO SAVE MAPPINGS to %s" % mapfile)
			print(e)
		return


	def loadMapping(self, mapfile="./mapping.json"):
		"""
			Restore internal mapping from saved JSON file
		"""
		try:
			fd = open(mapfile, "r")
			mappings = json.load(fd)
			if "Sharing" in mappings.keys():
				self.share_levels = mappings["Sharing"]
			if "Fields" in mapping.keys():
				self.field_map = mappings["Fields"]
			if "Type" in mapping.keys():
				self.type_map = mappings["Type"]
			fd.close()
		except Exception as e:
			print("IMPOSSIBLE TO LOAD MAPPINGS from %s" % mapfile)
			print(e)
		return

# --------------------------------------------------------------------------- #

def fromFacebookToMISP():
	# Open connection to MISP w/ proxy handling if required
	proxies = None
	if configuration.MISP_PROXY:
		proxies = configuration.PROXIES
	misp = MISP(configuration.MISP_URI, configuration.MISP_API, proxies)
	misp.saveMapping() #TEMP - DEBUG -- to replace by a load

	# Connect to Facebook Threat Exchange	
	proxies = None
	if configuration.TX_PROXY:
		proxies = configuration.PROXIES
	fb = FacebookTE(configuration.TX_APP_ID, configuration.TX_APP_SECRET, proxies)

	# Retrieve event from Facebook
	threats = fb.retrieveThreatDescriptorsLastNDays(1)
	for event in threats["data"]:
		mispevent = misp.convertTEtoMISP(event)
		jmispevent = misp.createEvent(mispevent)
		print("DEBUG: %s" % jmispevent)
		break #DEBUG - don't kill MISP ;)

	# All done ;)
	return

"""
    Main function
"""
def main():

	# TODO - handle the other way round
	fromFacebookToMISP()

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