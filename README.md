# MISP-ThreatExchange

Small script to retrieve information from Facebook Threat Exchange and push to MISP.
In the future, the script should also take the info from MISP and share back to Threat Exchange

## Installation

1. Install the required dependencies
<pre>
sudo pip install pymisp
sudo pip install requests
sudo pip install ast
</pre>

1. Copy the script <tt>default-configuration.py</tt> to <tt>configuration.py</tt>

## Configuration

The script take a part of his configuration from <tt>configuration.py</tt> that HAD to stay in the same directory than <tt>Facebook2ISP.py</tt>.

Important variables are:

1. Facebook API configuration:
<pre>
# Facebook Threat Exchange
TX_APP_ID="1234567890"     # Facebook AP ID as given in the app dashboard
TX_APP_SECRET="azertyuiop" # Facebook AP secret as given in the app dashboard
TX_PROXY=False             # set to True if proxy has to be used to communicate to Facebook
</pre>

1. MISP configuration
<pre>
# MISP
MISP_URI="https://10.20.30.40/" # MISP URL
MISP_API="azertyuiop"           # MISP API key as available inside MISP user profile
MISP_PROXY=False                # set to True if proxy has to be used to communicate with MISP instance
</pre>

1. Proxy configuration
<pre>
# Proxy configuration
# PROXIES = None if no proxy are required.  Otherwise, put the following format
PROXIES= {
	'http'  : "http://<user>:<pass>@<proxy addr>:<proxy port>",
	'https' : "http://<user>:<pass>@<proxy addr>:<proxy port>"
}
</pre>

## Usage

TODO :)

## Bugs...

The script probably contains bugs or missing features.  Feel free to open Issues on this GitHub project.

## References:

1. Facebook Threat Exchange: https://developers.facebook.com/docs/threat-exchange/v2.8
1. MISP project: http://www.misp-project.org/
