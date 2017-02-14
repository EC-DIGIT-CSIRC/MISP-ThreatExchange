# Copy this file to configuration.py

# Facebook Threat Exchange
TX_APP_ID=""
TX_APP_SECRET=""
TX_PROXY=False   # set to True if proxy configuration is required to reach Facebook

# MISP
MISP_URI="https://10.20.30.40"
MISP_API=""
MISP_PROXY=False  # set to True if proxy configuration is required to reach MISP

# Proxy configuration (if needed)
# format:
#	PROXIES= {
#		'http'  : "http://([username]:[password])@[host]:[port]",
#		'https' : "http://([username]:[password])@[host]:[port]"
#	}
PROXIES=None