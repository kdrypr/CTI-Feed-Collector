import csv
import json
import os
import pytz
from datetime import datetime
from itertools import islice
from urllib.request import Request, urlopen

tz = pytz.timezone('Europe/Istanbul')


def iocfeed():
    req = Request('https://iocfeed.mrlooquer.com/feed.json', headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read()
    output = json.loads(data)
    with open('iocfeed.json', 'w') as iocfeed_file:
        json.dump(output, iocfeed_file)
    iocfeed_file.close()
    # split single line json
    readFiles = open('iocfeed.json', 'r')
    jsonData = readFiles.readline()
    d = "},"
    # split but keep delimeter
    jsonData = [e + d for e in jsonData.split(d) if e]
    with open("lastIOCFeed.json", 'a') as iocJson:
        for data in jsonData[:-1]:
            iocJson.write(data[1:-1] + "\n")
            if data == jsonData[:-1]:
                iocJson.write(data[:-2])
    iocJson.close()
    os.remove('iocfeed.json')
    os.rename('lastIOCFeed.json', 'iocfeed.json')


def openphish():
    TurkeyTime = datetime.now(tz)
    req = Request('https://openphish.com/feed.txt', headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read().decode('utf-8')
    data = data.split("\n")
    for line in data:
        with open('openphish.json', 'a') as openphish_file:
            openphish_file.write("{\"url\":\"" + line + "\", \"category\": \"phishing\", \"last_update\": \"" + str(
                TurkeyTime) + "\"}\n")
    openphish_file.close()


def urlhaus():
    req = Request('https://urlhaus.abuse.ch/downloads/csv_online/', headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read().decode('utf-8')
    dataLast = data[9:]
    with open('urlhaus.csv', 'w') as urlhaus_csv_file:
        urlhaus_csv_file.write(dataLast)
    with open('urlhaus.csv', 'r') as fin, open('urlhaus2.csv', 'w') as fout:
        newFile = islice(fin, 9, None)
        fout.writelines(newFile)
    os.remove('urlhaus.csv')
    os.rename('urlhaus2.csv', 'urlhaus.csv')
    csvFile = open('urlhaus.csv', 'r')
    jsonFile = open('urlhaus.json', 'w')
    fieldNames = ("id", "dateadded", "url", "url_status", "threat", "tags", "urlhaus_link", "reporter")
    reader = csv.DictReader(csvFile, fieldNames)
    for row in reader:
        json.dump(row, jsonFile)
        jsonFile.write("\n")
    os.remove('urlhaus.csv')


def malshare():
    req = Request(
        'https://www.malshare.com/api.php?api_key=b1fdb5df9234be52e5cc755bc6d32ff9324874b1032eb240498a19a9665bb2b2&action=getlist',
        headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read()
    output = json.loads(data)
    with open('malshare.json', 'w') as malshare_file:
        json.dump(output, malshare_file)
    malshare_file.close()
    # split single line json
    readFiles = open('malshare.json', 'r')
    jsonData = readFiles.readline()
    d = "},"
    # split but keep delimeter
    jsonData = [e + d for e in jsonData.split(d) if e]
    with open("lastmalshare.json", 'a') as malshare_Json:
        for data in jsonData[:-1]:
            malshare_Json.write(data[1:-1] + "\n")
            if data == jsonData[:-1]:
                malshare_Json.write(data[:-2])
    malshare_Json.close()
    os.remove('malshare.json')
    os.rename('lastmalshare.json', 'malshare.json')


def sslblAbuse():
    req = Request('https://sslbl.abuse.ch/blacklist/sslipblacklist.csv', headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read().decode('utf-8')
    with open('sslblAbuse.csv', 'w') as sslblAbuse_file:
        sslblAbuse_file.write(data)
    with open('sslblAbuse.csv', 'r') as fin, open('sslblAbuse2.csv', 'w') as fout:
        newFile = islice(fin, 9, None)
        fout.writelines(newFile)
    os.remove('sslblAbuse.csv')
    os.rename('sslblAbuse2.csv', 'sslblAbuse.csv')
    csvFile = open('sslblAbuse.csv', 'r')
    jsonFile = open('sslblAbuse.json', 'w')
    fieldNames = ("Firstseen", "DstIP", "DstPort")
    reader = csv.DictReader(csvFile, fieldNames)
    for row in reader:
        json.dump(row, jsonFile)
        jsonFile.write("\n")
    os.remove('sslblAbuse.csv')


def feodotrackerAbuse():
    req = Request('https://feodotracker.abuse.ch/downloads/ipblocklist.csv', headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read().decode('utf-8')
    dataLast = data[9:]
    with open('feodotrackerAbuse.csv', 'w') as feodotrackerAbuse_file:
        feodotrackerAbuse_file.write(dataLast)
    with open('feodotrackerAbuse.csv', 'r') as fin, open('feodotrackerAbuse2.csv', 'w') as fout:
        newFile = islice(fin, 9, None)
        fout.writelines(newFile)
    os.remove('feodotrackerAbuse.csv')
    os.rename('feodotrackerAbuse2.csv', 'feodotrackerAbuse.csv')
    csvFile = open('feodotrackerAbuse.csv', 'r')
    jsonFile = open('feodotrackerAbuse.json', 'w')
    fieldNames = ("Firstseen", "DstIP", "DstPort", "LastOnline", "Malware")
    reader = csv.DictReader(csvFile, fieldNames)
    for row in reader:
        json.dump(row, jsonFile)
        jsonFile.write("\n")
    os.remove('feodotrackerAbuse.csv')


def IPSpamList():
    req = Request('http://www.ipspamlist.com/public_feeds.csv', headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read().decode('utf-8')
    dataLast = data[9:]
    with open('IPSpamList.csv', 'w') as feodotrackerAbuse_file:
        feodotrackerAbuse_file.write(dataLast)
    with open('IPSpamList.csv', 'r') as fin, open('IPSpamList2.csv', 'w') as fout:
        newFile = islice(fin, 10, None)
        fout.writelines(newFile)
    os.remove('IPSpamList.csv')
    os.rename('IPSpamList2.csv', 'IPSpamList.csv')
    csvFile = open('IPSpamList.csv', 'r')
    jsonFile = open('IPSpamList.json', 'w')
    fieldNames = ("first_seen", "last_seen", "ip_address", "category", "attack_count")
    reader = csv.DictReader(csvFile, fieldNames)
    for row in reader:
        json.dump(row, jsonFile)
        jsonFile.write("\n")
    os.remove('IPSpamList.csv')


def charlesTheHaleysSSHAttacks():
    req = Request('http://charles.the-haleys.org/ssh_dico_attack_hdeny_format.php/hostsdeny.txt',
                  headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read().decode('utf-8')
    dataLast = data[2:]
    with open('charlesTheHaleysSSHAttacks.txt', 'w') as fin:
        fin.write(dataLast)
    readFile = open('charlesTheHaleysSSHAttacks.txt', 'r')
    for row in readFile:
        lastRow = row.split(':')
        with open('charlesTheHaleysSSHAttacks.json', 'a') as charlesTheHaleysSSHAttacks_file:
            charlesTheHaleysSSHAttacks_file.write(
                "{\"IPAddress\":\"" + lastRow[1].strip() + "\", \"category\": \"ssh_attack\"}\n")
    os.remove('charlesTheHaleysSSHAttacks.txt')


def blocklistDE():
    # Get time with unixtime format
    time = datetime.strftime(datetime.utcnow(), "%s")
    TurkeyTime = datetime.now(tz)
    # For SSH
    serviceList = ["apache", "bots", "mail", "imap", "ftp", "ssh", "voip"]
    for service in serviceList:
        req = Request('http://api.blocklist.de/getlast.php?time=' + time + '&service=' + service,
                      headers={'User-Agent': 'Mozilla/5.0'})
        data = urlopen(req).read().decode('utf-8')
        if data:
            data = data.split("\n")
            for IP in data:
                if IP:
                    with open('blocklistDE.json', 'a') as blocklistDE_file:
                        blocklistDE_file.write(
                            "{\"IPAddress\":\"" + IP + "\", \"category\": \"attack\", \"subcategory\": \"" + service + "\", \"last_update\": \"" + str(
                                TurkeyTime) + "\" }\n")
            blocklistDE_file.close()
        else:
            print("There is no data on " + str(TurkeyTime) + " in " + service)


if __name__ == '__main__':
    iocfeed()
    openphish()
    urlhaus()
    malshare()
    sslblAbuse()
    feodotrackerAbuse()
    IPSpamList()
    charlesTheHaleysSSHAttacks()
    blocklistDE()
