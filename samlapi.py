#!/usr/bin/env python3

import argparse
import sys 
import boto3
import requests 
import getpass 
import configparser 
import base64 
import xml.etree.ElementTree as ET 
import os
from bs4 import BeautifulSoup 
from os.path import expanduser 
from urllib.parse import urlparse, urlunparse 
from requests_ntlm import HttpNtlmAuth

######
class ConfigSettings:
	def __init__(self, commandLineArguments):
		self.username = commandLineArguments.getUser() 
		self.domain = commandLineArguments.getDomain() 
		self.filter = commandLineArguments.getFilter()
		self.tokenDuration = commandLineArguments.getTokenDuration()
		self.profile = commandLineArguments.getProfile()
		if commandLineArguments.getAsk(): self.askUser()

	def askUser(self):
		self.domain = self.inputWithDefault('Enter domain ({}):', self.domain)
		self.username = self.inputWithDefault('Enter username ({}):', self.username)
		self.profile = self.inputWithDefault('Enter profile ({}):', self.profile)
		
	def inputWithDefault (self, display, default):
		value = input(display.format(default))
		if len(value) == 0: value = default
		return value
		
	def getTokenDuration(self):
		return int(self.tokenDuration)

	def getUsername(self): 
		return self.username + '@' + self.domain + '.rootdom.dk'

	def getFilter(self):
		return self.filter

	def getPassword(self): 
		return self.password 
 
	def askPassword(self): 
		self.password = getpass.getpass()
		

	def getProfile(self):
		return self.profile

class CommandLineArguments: 
	def __init__(self): 
		self.parser = argparse.ArgumentParser()
		self.parser.add_argument("-p", "--profile", help="Specify which profile name to store settings in.", default="default")
		self.parser.add_argument("-u", "--user", help="Specify username to user. Don't specify any domain information", default=getpass.getuser())
		self.parser.add_argument("-d", "--domain", help="Specify domain. Defaults to the userdomain environment and if not polhus", default=os.environ.get('userdomain', "polhus"))
		self.parser.add_argument("-a", "--ask", help="Ask user for all values. Defaults from other command line arguments", action='store_true')
		self.parser.add_argument("-td", "--tokenDuration", help="Token duration in seconds. Default is 3600 which is the default in AWS, but generally speaking longer durations are more convenient.", default="3600")
		self.parser.add_argument("-f", "--filter", help="Filter for returned role values. Specify full name (or unique match) to avoid selecting role and login directly.", default = "")
		self.args = self.parser.parse_args()

	def getProfile(self):
		return self.args.profile

	def getUser(self):
		return self.args.user

	def getDomain(self):
		return self.args.domain

	def getTokenDuration(self): 
		return self.args.tokenDuration

	def getAsk(self):
		return self.args.ask

	def getFilter(self):
		return self.args.filter


class AwsConfigFile:
	def __init__(self, profile, configfile = '/.aws/credentials', region = 'eu-west-1', outputformat = 'json'):
		self.__profile = profile
		# awsconfigfile: The file where this script will store the temp credentials under the saml profile 
		self.__awsconfigfile = configfile
		# region: The default AWS region that this script will connect to for all API calls 
		self.__region = region
		# output format: The AWS CLI output format that will be configured in the saml profile (affects subsequent CLI calls) 
		self.__outputformat = outputformat
		self.filename = expanduser("~") + configfile
		pass

	def update(self, credentials):
		"""Update configuration file with security credentials from STS client"""
		# Read in the existing config file
		config = configparser.RawConfigParser()
		config.read(self.filename)
		
		# Put the credentials into a specific profile instead of clobbering
		# the default credentials
		if not config.has_section(self.__profile):
			config.add_section(self.__profile)
		
		config.set(self.__profile, 'output', self.__outputformat)
		config.set(self.__profile, 'region', self.__region)
		config.set(self.__profile, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
		config.set(self.__profile, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
		config.set(self.__profile, 'aws_session_token', token['Credentials']['SessionToken'])
		
		# Write the updated config file
		with open(self.filename, 'w+') as configfile:
			config.write(configfile)

################################################################################
# Functions 

def getAssertionFromResponse(response):
	assertion = ''
	# Decode the response and extract the SAML assertion 
	soup = BeautifulSoup(response.text, features="html.parser") 
	# Look for the SAMLResponse attribute of the input tag (determined by 
	# analyzing the debug print(lines above) )
	for inputtag in soup.find_all('input'): 
	    if(inputtag.get('name') == 'SAMLResponse'): 
	        #print(inputtag.get('value')) 
	        assertion = inputtag.get('value')
	return assertion
 
################################################################################

##########################################################################
# Variables 
commandLineArguments = CommandLineArguments()
  
# SSL certificate verification: Whether or not strict certificate 
# verification is done, False should only be used for dev/test 
sslverification = True 
 
# idpentryurl: The initial URL that starts the authentication process. 
idpentryurl = 'https://sts.rootdom.dk/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices' 

##########################################################################

# Get the federated credentials from the user
settings = ConfigSettings(commandLineArguments)
print('')
print('Will use the username {}'.format(settings.getUsername()))
settings.askPassword()

# Initiate session handler 
session = requests.Session() 
 
# Programatically get the SAML assertion 
# Set up the NTLM authentication handler by using the provided credential 
session.auth = HttpNtlmAuth(settings.getUsername(), settings.getPassword(), session) 
 
# Opens the initial AD FS URL and follows all of the HTTP302 redirects 
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0'}
response = session.get(idpentryurl, headers=headers, verify=sslverification) 
 
# Debug the response if needed 
print(response)

assertion = getAssertionFromResponse(response)

try:
	root = ET.fromstring(base64.b64decode(assertion))
except: 
	print('An exception occurred using NTLM negotiation. retrying with post to sts.rootdom.dk')
	payload = {'UserName': settings.getUsername(), 'Password': settings.getPassword(), 'optionForms': 'FormsAuthentication' }
	session.auth = None
	session.get(url = idpentryurl, headers = headers, verify = sslverification)
	response = session.post(url = idpentryurl, headers=headers, verify=sslverification, data = payload)
	assertion = getAssertionFromResponse(response)
	root = ET.fromstring(base64.b64decode(assertion))
	print(root)

 
## Get account and role names
r = session.post("https://signin.aws.amazon.com/saml", data={"SAMLResponse": assertion})
soup = BeautifulSoup(r.text, features="html.parser")

accounts_elm = soup.find_all("div", class_="saml-account")
accounts = []
num_roles = 0
for acc in accounts_elm:
	try:
		account_name = acc.find("div", class_="saml-account-name").get_text().replace("Account: ", "")
		account_roles = []
		roles_elm = acc.find_all("div", class_="saml-role")
		for role in roles_elm:
			role_name = role.find("label").get_text()
			role_arn = role.find("input")["value"]
			account_roles.append({"arn": role_arn, "name": role_name})
			num_roles += 1
		accounts.append({"name": account_name, "roles": account_roles})
	except Exception as e:
		continue

# Overwrite and delete the credential variables, just for safety
username = '##############################################'
password = '##############################################'
del username
del password

for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'): 
	if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'): 
		for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
			principal, role_arn = saml2attributevalue.text.split(',')

			## add principal to accounts
			for account in accounts:
				for role in account["roles"]:
					if role["arn"] == role_arn:
						role["principal"] = principal

# If I have more than one role, ask the user which one they want, 
# otherwise just proceed 
print("" )
if num_roles > 1:
	i = 0
	print("Please choose the role you would like to assume:" )
	# for awsrole in awsroles:
		# print('[', i, ']: ', awsrole.split(',')[0] )
		# i += 1
	for account in accounts:
		print(account["name"])
		for role in account["roles"]:
			print(f" [{i}] {role['name']}")
			i += 1

	print("Selection: ", )
	selectedroleindex = input()



	# Find selected role
	selected_role = None
	i = 0
	for account in accounts:
		for role in account["roles"]:
			if int(selectedroleindex) == i:
				selected_role = role
			i += 1

	if selected_role == None:
		print('You selected an invalid role index, please try again' )
		sys.exit(0)

	role_arn = selected_role['arn']
	principal_arn = selected_role['principal']

elif num_roles == 1:
	role_arn = accounts[0]["roles"][0]["arn"]
	principal_arn = accounts[0]["roles"][0]["principal"]
else:
	print ("No roles returned. (If you have provided a filter you might test the unfiltered result.")
	quit()


# Use the assertion to get an AWS STS token using Assume Role with SAML
conn = boto3.client('sts')
token = conn.assume_role_with_saml(RoleArn = role_arn, PrincipalArn = principal_arn, SAMLAssertion = assertion, DurationSeconds = settings.getTokenDuration())

print(token)
# Write the AWS STS token into the AWS credential file
awsCondigFile = AwsConfigFile(settings.getProfile())
awsCondigFile.update(token)

# Give the user some basic info as to what has just happened
print('\n\n----------------------------------------------------------------')
print('Your new access key pair has been stored in the AWS configuration file {0} under the saml profile.'.format(awsCondigFile.filename))
print('Note that it will expire at {0}.'.format(token['Credentials']['Expiration']))
print('After this time you may safely rerun this script to refresh your access key pair.')
print('To use this credential call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).')
print('----------------------------------------------------------------\n\n')

iamid = token['AssumedRoleUser']['Arn']

print('Assumed role is:')
print(iamid)
