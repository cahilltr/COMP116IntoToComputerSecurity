import csv
import re
import json
from urllib.request import urlopen

filePath = sys.argv[1]

ipv4List = list()
with open(filePath) as csvfile:
	readCSV = csv.reader(csvfile, delimiter=',')
	for row in readCSV:
		if row[1] == 'IPV4ADDR':
			ipv4List.append(row[0])

cleanIPList = list()
for ip in ipv4List:
	cleanIPList.append(ip.replace("[", "").replace("]",""))

print(cleanIPList)
regionList = list()
countryCounts = {}
for cleanIp in reversed(cleanIPList):
	url = "http://" + cleanIp
	print(url)
	try:
		response = urlopen(url)
		data = json.load(response)

		IP=data['ip']
		org=data['org']
		city = data['city']
		country=data['country']
		if country in countryCounts:
			countryCounts[country] = countryCounts[countryCounts] + 1
		else:
			countryCounts[country] = 1
		region=data['region']
		regionList.append("IP : {4} Region : {1} Country : {2} City : {3} Org : {0}".format(org,region,country,city,IP))
		print("IP : {4} Region : {1} Country : {2} City : {3} Org : {0}".format(org,region,country,city,IP))
	except Exception as e:
		print("Unexpected error:" + str(e))
		continue

print(countryCounts)		