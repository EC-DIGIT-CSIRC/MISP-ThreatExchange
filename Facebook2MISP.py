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

from pytx.access_token import access_token
from pytx import ThreatDescriptor
from pytx import ThreatIndicator
from pytx.vocabulary import ThreatDescriptor as td
from pymisp import PyMISP # MISP API


def retrieveEventsFromFacebook():
	indicators = ThreatIndicator.objects(
		limit=1000,
	)
	
	for indicator in indicators:
		print indicator  # debug

	return indicators


"""
    Main function
"""
def main():
	# Validate if credential for Facebook are available
	if 'TX_APP_ID' not in os.environ or 'TX_APP_SECRET' not in os.environ:
		print("Facebook Threat Exchange credential unavailable :'(.")
		sys.exit(-1)

	print("READY to GO :)") # DEBUG

	# Retrieve event from Facebook
	retrieveEventsFromFacebook()

	# All done ;)
	return


"""
   Call main function
"""
if __name__ == "__main__":
    
    # Create an instance of the Analysis class (called "base") and run main 
    main()

# That's all folks ;)