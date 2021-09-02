# CTI-Feeder
Open Source Cyber Threat Intelligence Feed Collector

## Installation

* pip3 install -r requirements.txt


## Start

* python3.8 cti_feeder.py

## How to

**The script collect the data from all the specified sources, converts it to json format and writes it to the files with the source name.**

![GitHub Logo](/feed.png)

![GitHub Logo](/elastic.png)

## Feed Resources
* iocfeed.mrlooquer.com
* openphish.com
* urlhaus.abuse.ch
* www.malshare.com
* sslbl.abuse.ch
* feodotracker.abuse.ch
* www.ipspamlist.com
* charles.the-haleys.org
* api.blocklist.de

## Roadmap

- [X] Writing to JSON file
- [X] Elasticsearch import added
- [X] Archive system added 
- [ ] New resources will be added
- [ ] CSV export option
- [ ] Scheduled feed update
- [ ] Search from archive

