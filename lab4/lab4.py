import csv
import sys
import json
import pygeoip

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

gi = pygeoip.GeoIP('/usr/share/GeoIP/GeoIP.dat',
                   flags=pygeoip.const.MMAP_CACHE)

countryCounts = {}

for cleanIp in reversed(cleanIPList):
	country = gi.country_code_by_addr(cleanIp)
	if country in countryCounts:
		countryCounts[country] = countryCounts[country] + 1
	else:
		countryCounts[country] = 1

print(countryCounts)		