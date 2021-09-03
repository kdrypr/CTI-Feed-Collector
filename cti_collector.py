import csv, json, os, zipfile, pytz, logging, click, requests, wget, sys, time, schedule
from datetime import datetime
from itertools import islice
from urllib.request import Request, urlopen
from elasticsearch import Elasticsearch
from pathlib import Path

tz = pytz.timezone('Europe/Istanbul')
logging.basicConfig(filename='CTI.log', filemode='a', format='%(asctime)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO)
elasticUrl = 'http://localhost:9200/'
es = Elasticsearch([elasticUrl])


def createFolders():
    if not os.path.isdir("files"):
        os.mkdir("files")
        logging.info('Folder not found! Files folder created.')

    if not os.path.isdir("archive"):
        os.mkdir("archive")
        logging.info('Folder not found! Archive folder created.')

    if not os.path.isdir("downloads"):
        os.mkdir("downloads")
        logging.info('Folder not found! Downloads folder created.')


def installElasticsearch():
    if click.confirm('Do you want to install Elasticsearch?', default=True):
        print("Elasticsearch bundle does not need java. Java included.")
        wget.download('https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.14.1-amd64.deb',
                      out='downloads')
        command = 'dpkg -i downloads/elasticsearch-7.14.1-amd64.deb'
        os.system('sudo -S %s' % (command))


def installKibana():
    if click.confirm('Do you want to install Kibana?', default=True):
        wget.download('https://artifacts.elastic.co/downloads/kibana/kibana-7.14.1-amd64.deb', out='downloads')
        command = 'dpkg -i downloads/kibana-7.14.1-amd64.deb'
        os.system('sudo -S %s' % (command))


def configureServices():
    try:
        # Elasticsearch Configuration
        file = Path('/etc/elasticsearch/elasticsearch.yml')
        file.write_text(file.read_text().replace('#node.name: node-1', 'node.name: node-1'))
        file.write_text(file.read_text().replace('#network.host: localhost', 'network.host: localhost'))
        file.write_text(file.read_text().replace('#http.port: 9200', 'http.port: 9200'))

        file = Path('/etc/kibana/kibana.yml')
        file.write_text(file.read_text().replace('#elasticsearch.hosts: ["http://localhost:9200"]',
                                                 'elasticsearch.hosts: ["http://localhost:9200"]'))
        file.write_text(file.read_text().replace('#server.host: "localhost"', 'server.host: "localhost"'))
        file.write_text(file.read_text().replace('#server.port: 5601', 'server.port: 5601'))

        os.system("service elasticsearch restart")
        os.system("service kibana restart")
    except:
        print("Permission denied! Please run script with sudo privileges!")
        logging.info("Permission denied! Script did not run with sudo privileges!")


def postElastic():
    directory = 'files/'
    for filename in os.listdir(directory):
        index = []
        if filename.endswith('.json'):
            with open(directory + filename) as f:
                index = filename.split(".")
                esIndex = index[0]
                elasticIndex = "cti_" + esIndex
                es.indices.create(index=elasticIndex.lower(), ignore=400)
                for line in f:
                    headers = {'content-type': 'application/json'}
                    request = requests.post(elasticUrl + elasticIndex + "/_doc", data=line, headers=headers)


def iocfeed():
    req = Request('https://iocfeed.mrlooquer.com/feed.json', headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read()
    output = json.loads(data)
    with open('files/iocfeed.json', 'w') as iocfeed_file:
        json.dump(output, iocfeed_file)
    iocfeed_file.close()
    # split single line json
    readFiles = open('files/iocfeed.json', 'r')
    jsonData = readFiles.readline()
    d = "},"
    # split but keep delimeter
    jsonData = [e + d for e in jsonData.split(d) if e]
    with open("files/lastIOCFeed.json", 'a') as iocJson:
        for data in jsonData[:-1]:
            iocJson.write(data[1:-1] + "\n")
            if data == jsonData[:-1]:
                iocJson.write(data[:-2])
    iocJson.close()
    os.remove('files/iocfeed.json')
    os.rename('files/lastIOCFeed.json', 'files/iocfeed.json')
    zipfile.ZipFile('archive/iocfeed.zip', mode='w').write('files/iocfeed.json', arcname='iocfeed.json')
    logging.info('Mrlooquer IOC Feeds updated and zipped.')


def openphish():
    TurkeyTime = datetime.now(tz)
    req = Request('https://openphish.com/feed.txt', headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read().decode('utf-8')
    data = data.split("\n")
    for line in data:
        with open('files/openphish.json', 'a') as openphish_file:
            openphish_file.write("{\"url\":\"" + line + "\", \"category\": \"phishing\", \"last_update\": \"" + str(
                TurkeyTime) + "\"}\n")
    openphish_file.close()
    zipfile.ZipFile('archive/openphish.zip', mode='w').write('files/openphish.json', arcname='openphish.json')
    logging.info('Openphish feeds updated and zipped.')


def urlhaus():
    req = Request('https://urlhaus.abuse.ch/downloads/csv_online/', headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read().decode('utf-8')
    dataLast = data[9:]
    with open('files/urlhaus.csv', 'w') as urlhaus_csv_file:
        urlhaus_csv_file.write(dataLast)
    with open('files/urlhaus.csv', 'r') as fin, open('files/urlhaus2.csv', 'w') as fout:
        newFile = islice(fin, 9, None)
        fout.writelines(newFile)
    os.remove('files/urlhaus.csv')
    os.rename('files/urlhaus2.csv', 'files/urlhaus.csv')
    csvFile = open('files/urlhaus.csv', 'r')
    jsonFile = open('files/urlhaus.json', 'w')
    fieldNames = ("id", "dateadded", "url", "url_status", "threat", "tags", "urlhaus_link", "reporter")
    reader = csv.DictReader(csvFile, fieldNames)
    for row in reader:
        json.dump(row, jsonFile)
        jsonFile.write("\n")
    os.remove('files/urlhaus.csv')
    zipfile.ZipFile('archive/urlhaus.zip', mode='w').write('files/urlhaus.json', arcname='urlhaus.json')
    logging.info('URLHAUS feed updated.')


def malshare():
    req = Request(
        'https://www.malshare.com/api.php?api_key=b1fdb5df9234be52e5cc755bc6d32ff9324874b1032eb240498a19a9665bb2b2&action=getlist',
        headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read()
    output = json.loads(data)
    with open('files/malshare.json', 'w') as malshare_file:
        json.dump(output, malshare_file)
    malshare_file.close()
    # split single line json
    readFiles = open('files/malshare.json', 'r')
    jsonData = readFiles.readline()
    d = "},"
    # split but keep delimeter
    jsonData = [e + d for e in jsonData.split(d) if e]
    with open("files/lastmalshare.json", 'a') as malshare_Json:
        for data in jsonData[:-1]:
            malshare_Json.write(data[1:-1] + "\n")
            if data == jsonData[:-1]:
                malshare_Json.write(data[:-2])
    malshare_Json.close()
    os.remove('files/malshare.json')
    os.rename('files/lastmalshare.json', 'files/malshare.json')
    zipfile.ZipFile('archive/malshare.zip', mode='w').write('files/malshare.json', arcname='malshare.json')
    logging.info('Malshare feeds updated and zipped.')


def sslblAbuse():
    req = Request('https://sslbl.abuse.ch/blacklist/sslipblacklist.csv', headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read().decode('utf-8')
    with open('files/sslblAbuse.csv', 'w') as sslblAbuse_file:
        sslblAbuse_file.write(data)
    with open('files/sslblAbuse.csv', 'r') as fin, open('files/sslblAbuse2.csv', 'w') as fout:
        newFile = islice(fin, 9, None)
        fout.writelines(newFile)
    os.remove('files/sslblAbuse.csv')
    os.rename('files/sslblAbuse2.csv', 'files/sslblAbuse.csv')
    csvFile = open('files/sslblAbuse.csv', 'r')
    jsonFile = open('files/sslblAbuse.json', 'w')
    fieldNames = ("Firstseen", "DstIP", "DstPort")
    reader = csv.DictReader(csvFile, fieldNames)
    for row in reader:
        json.dump(row, jsonFile)
        jsonFile.write("\n")
    os.remove('files/sslblAbuse.csv')
    zipfile.ZipFile('archive/sslblAbuse.zip', mode='w').write('files/sslblAbuse.json', arcname='sslblAbuse.json')
    logging.info('SSL BL ABUSE feeds updated and zipped.')


def feodotrackerAbuse():
    req = Request('https://feodotracker.abuse.ch/downloads/ipblocklist.csv', headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read().decode('utf-8')
    dataLast = data[9:]
    with open('files/feodotrackerAbuse.csv', 'w') as feodotrackerAbuse_file:
        feodotrackerAbuse_file.write(dataLast)
    with open('files/feodotrackerAbuse.csv', 'r') as fin, open('files/feodotrackerAbuse2.csv', 'w') as fout:
        newFile = islice(fin, 9, None)
        fout.writelines(newFile)
    os.remove('files/feodotrackerAbuse.csv')
    os.rename('files/feodotrackerAbuse2.csv', 'files/feodotrackerAbuse.csv')
    csvFile = open('files/feodotrackerAbuse.csv', 'r')
    jsonFile = open('files/feodotrackerAbuse.json', 'w')
    fieldNames = ("Firstseen", "DstIP", "DstPort", "LastOnline", "Malware")
    reader = csv.DictReader(csvFile, fieldNames)
    for row in reader:
        json.dump(row, jsonFile)
        jsonFile.write("\n")
    os.remove('files/feodotrackerAbuse.csv')
    zipfile.ZipFile('archive/feodotrackerAbuse.zip', mode='w').write('files/feodotrackerAbuse.json',
                                                                     arcname='feodotrackerAbuse.json')
    logging.info('Feodo Tracker feeds updated and zipped.')


def IPSpamList():
    req = Request('http://www.ipspamlist.com/public_feeds.csv', headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read().decode('utf-8')
    dataLast = data[9:]
    with open('files/IPSpamList.csv', 'w') as feodotrackerAbuse_file:
        feodotrackerAbuse_file.write(dataLast)
    with open('files/IPSpamList.csv', 'r') as fin, open('files/IPSpamList2.csv', 'w') as fout:
        newFile = islice(fin, 10, None)
        fout.writelines(newFile)
    os.remove('files/IPSpamList.csv')
    os.rename('files/IPSpamList2.csv', 'files/IPSpamList.csv')
    csvFile = open('files/IPSpamList.csv', 'r')
    jsonFile = open('files/IPSpamList.json', 'w')
    fieldNames = ("first_seen", "last_seen", "ip_address", "category", "attack_count")
    reader = csv.DictReader(csvFile, fieldNames)
    for row in reader:
        json.dump(row, jsonFile)
        jsonFile.write("\n")
    os.remove('files/IPSpamList.csv')
    zipfile.ZipFile('archive/IPSpamList.zip', mode='w').write('files/IPSpamList.json', arcname='IPSpamList.json')
    logging.info('IP Spam List feeds updated and zipped.')


def charlesTheHaleysSSHAttacks():
    req = Request('http://charles.the-haleys.org/ssh_dico_attack_hdeny_format.php/hostsdeny.txt',
                  headers={'User-Agent': 'Mozilla/5.0'})
    data = urlopen(req).read().decode('utf-8')
    dataLast = data[2:]
    with open('files/charlesTheHaleysSSHAttacks.txt', 'w') as fin:
        fin.write(dataLast)
    readFile = open('files/charlesTheHaleysSSHAttacks.txt', 'r')
    for row in readFile:
        lastRow = row.split(':')
        with open('files/charlesTheHaleysSSHAttacks.json', 'a') as charlesTheHaleysSSHAttacks_file:
            charlesTheHaleysSSHAttacks_file.write(
                "{\"IPAddress\":\"" + lastRow[1].strip() + "\", \"category\": \"ssh_attack\"}\n")
    os.remove('files/charlesTheHaleysSSHAttacks.txt')
    zipfile.ZipFile('archive/charlesTheHaleysSSHAttacks.zip', mode='w').write('files/charlesTheHaleysSSHAttacks.json',
                                                                              arcname='charlesTheHaleysSSHAttacks.json')
    logging.info('Charles The-Haleys feed updated.')


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
                    with open('files/blocklistDE.json', 'a') as blocklistDE_file:
                        blocklistDE_file.write(
                            "{\"IPAddress\":\"" + IP + "\", \"category\": \"attack\", \"subcategory\": \"" + service + "\", \"last_update\": \"" + str(
                                TurkeyTime) + "\" }\n")
            blocklistDE_file.close()
        else:
            print("There is no data on " + str(TurkeyTime) + " in " + service)
    zipfile.ZipFile('archive/blocklistDE.zip', mode='w').write('files/blocklistDE.json', arcname='blocklistDE.json')
    logging.info('Block List DE Services feeds updated.')


def feedService():
    iocfeed()
    openphish()
    urlhaus()
    malshare()
    sslblAbuse()
    feodotrackerAbuse()
    IPSpamList()
    charlesTheHaleysSSHAttacks()
    blocklistDE()


def scheduleService():
    sTime = input("Please input your interval value with minute type! : ")
    schedule.every(int(sTime)).minutes.do(feedService)
    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == '__main__':
    createFolders()
    installElasticsearch()
    installKibana()
    configureServices()
    feedService()

    if click.confirm('Do you want to import all cti json feeds to elasticsearch?', default=True):
        postElastic()

    if click.confirm('Do you want to update all feeds with scheduled?', default=True):
        scheduleService()
