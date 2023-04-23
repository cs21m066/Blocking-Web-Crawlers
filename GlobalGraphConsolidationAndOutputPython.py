#!/usr/bin/env python3

import pandas as pd
import numpy as np
import os
import re
from collections import defaultdict
from scipy.stats import zscore
from sklearn.preprocessing import MinMaxScaler
from sklearn.preprocessing import StandardScaler


foldername = "/usr/share/modsecurity-crs/graphBasedDistributedCrawlerDetector/iitmLogs/"
outfolder = "/usr/share/modsecurity-crs/graphBasedDistributedCrawlerDetector/outputFiles/"
log_files = os.listdir(foldername)

def removeIITMSearchParams(x):
    m = re.match(r"(?P<base>.*(search|403|robots[.]txt))[/?]", x)
    if m == None:
        return x
    return m.group("base")


rearranged = ["type", "subtype", "request", "ip", "ip_orig", "src_port", "useragent", "date", "time", "req_method", "req_host", "statuscode", "referrer"]

def getUsefulFilter(filename):
    unfilteredData = pd.read_csv(foldername + filename)
    onlyIITMData = unfilteredData.loc[(unfilteredData['req_host'].str.contains("www.iitm.ac.in", case = False)) & (unfilteredData['req_method'] == "get")]
    onlyIITMData = onlyIITMData[~onlyIITMData['request'].str.contains(r'[.](jpg|jpeg|css|js|png|woff|gif|svg|ico)')]
    processedRequests = [removeIITMSearchParams(x) for x in onlyIITMData['request']]
    onlyIITMData['request'] = processedRequests
    return onlyIITMData[rearranged]

isFirst = True
for file in os.listdir(foldername):
    filteredData = getUsefulFilter(file)
    if isFirst:
        filteredData.to_csv(os.path.join(outfolder, "filteredandcombined.csv"), index=False)
    else:
        filteredData.to_csv(os.path.join(outfolder, "filteredandcombined.csv"), index=False, header=isFirst, mode='a')
    isFirst = False

fullData = pd.read_csv(outfolder + "filteredandcombined.csv")

bots = fullData[(fullData["useragent"].str.contains("bot|amphtml|cloudflare|requests|spider|crawler", case=False)) | (fullData["useragent"] == "-")]
non_bots = fullData[~fullData["useragent"].str.contains("bot|amphtml|cloudflare|requests|spider|crawler", case=False)]
non_bots.to_csv(outfolder + "non_bots.csv", index=False)
bots.to_csv(outfolder + "bots.csv", index=False)

def getWeightedGraph(entries):
    weightedGraph = {}
    groupByIPDate = entries.groupby('date')

    for date, group in groupByIPDate:
        firstRequest = True
        prevReq = ""
        for idx, rec in group.iterrows():
            if firstRequest:
                firstRequest = False
                prevReq = rec['request']
                continue
            if rec['request'] == prevReq:
                continue
            edge = (prevReq, rec['request'])
            edge2 = (rec['request'], prevReq)
            count = weightedGraph.get(edge, 0)
            weightedGraph[edge] = count + 1
            weightedGraph[edge2] = count + 1
            prevReq = rec['request']
    return weightedGraph

def getGraphDf(data):
    weightedGraph = getWeightedGraph(data)
    sortedGraph = sorted(weightedGraph.items(), key=lambda x: x[1], reverse=True)
    source = [x[0][0] for x in sortedGraph]
    dest = [x[0][1] for x in sortedGraph]
    weight = [x[1] for x in sortedGraph]

    graphDf = pd.DataFrame({'source': source, 'destination': dest, 'weight': weight})
    return graphDf

fullGraph = getGraphDf(fullData)
botGraph = getGraphDf(bots)
nonBotGraph = getGraphDf(non_bots)

fullGraph.to_csv(os.path.join(outfolder, "servergraph.csv"))
botGraph.to_csv(os.path.join(outfolder, "botgraph.csv"))
nonBotGraph.to_csv(os.path.join(outfolder, "nonbotgraph.csv"))

# f = open(os.path.join(outfolder, "blockedIPs.txt"), "w+")
# f.write("127.0.0.1 -")
# f.close()

fullData = pd.read_csv(outfolder + "filteredandcombined.csv")
bots = fullData[(fullData["useragent"].str.contains("bot|amphtml|cloudflare|requests|spider|crawler", case=False)) | (fullData["useragent"] == "-")]
non_bots = fullData[~fullData["useragent"].str.contains("bot|amphtml|cloudflare|requests|spider|crawler", case=False)]

groupByIP = [x for _, x in non_bots.groupby("ip")]

highUserSet = set()
for group in groupByIP:
    if group["request"].nunique(dropna = True) > 9:
        highUserSet.add(group["ip"].iloc[0])
groupByIPfiltered = list(filter(lambda x:x["ip"].iloc[0] in highUserSet, groupByIP))


def getSingleIpGraph(g):
    weightedGraph = defaultdict(int)

    firstRequest = True
    prevReq = ""
    ip = ""
    date = ""
    for _, rec in g.iterrows():
        if firstRequest:
            firstRequest = False
            ip = rec["ip"]
            date = rec["date"]
            prevReq = rec["request"]
            continue
        if rec["request"] == prevReq:
            continue
        edge = (prevReq, rec["request"])
        weightedGraph[edge] += 1
        prevReq = rec["request"]

    sortedGraph = sorted(weightedGraph.items(), key=lambda x: x[1], reverse=True)

    source = [x[0][0] for x in sortedGraph]
    dest = [x[0][1] for x in sortedGraph]
    weight = [x[1] for x in sortedGraph]

    graphDf = pd.DataFrame({"source": source, "destination": dest, "weight": weight})

    return graphDf

serverGraph = {}
serverDf = pd.read_csv(outfolder + "servergraph.csv")
for _, row in serverDf.iterrows():
    serverGraph[(row["source"] + "=>" + row["destination"])] = row["weight"]

q = np.quantile(serverDf['weight'], 0.6)

def ipGraphSimilarity(gDf):
    numLowThresh = 0
    gamma = 15

    edgeWeightDict = {}
    for _, row in gDf.iterrows():
        edgeWeightDict[(row["source"] + "=>" + row["destination"])] = 1
        
    for edge in edgeWeightDict:
        if edge not in serverGraph:
            continue
        serverWeight = serverGraph[edge]
        if serverWeight <= gamma:
            numLowThresh += 1 
            
    return numLowThresh


def getUrlsAndUnique(ipaddr, filterGroup):
    selectGroup = filterGroup.loc[filterGroup['ip'] == ipaddr]
    urls = selectGroup.shape[0]
    uniqueUrls = selectGroup['request'].nunique()
    return urls, uniqueUrls


def getScoreDf(group):
    similarityResultsUser = {}
    posResUser = {}
    penResUser = {}
    urlsUser = {}
    numUniqueUser = {}
    useragent = {}
    anomalyRatio = {}
    dateUser = {}

    graphSizes = []
    for ipGroup in group:
        maxThresh = 0
        prevThresh = 0
        anomaly = 0
        ipaddr = ipGroup['ip'].iloc[0]
        dateDataList = [x for _, x in ipGroup.groupby("date")]
        for dateData in dateDataList:
            graph = getSingleIpGraph(dateData)
            score = ipGraphSimilarity(graph)
            if score >= maxThresh:
                maxThresh = max(maxThresh, score)
                prevThresh = score
                urlsUniques = getUrlsAndUnique(ipaddr, dateData)
                urlsUser[ipaddr] = urlsUniques[0]
                numUniqueUser[ipaddr] = urlsUniques[1]
                dateUser[ipaddr] = dateData['date'].iloc[0]
                if graph.shape[0] == 0:
                    anomaly = 923456789
                else:
                    anomaly = maxThresh / graph.shape[0]
            
        similarityResultsUser[ipaddr] = maxThresh
        useragent[ipaddr] = ipGroup['useragent'].iloc[0]
        anomalyRatio[ipaddr] = anomaly
    simUserDf = pd.DataFrame({
        'ip': list(similarityResultsUser.keys()),
        'date': list(dateUser.values()),
        'score': list(similarityResultsUser.values()),
        'numUrl': list(urlsUser.values()),
        'numUniqueUser': list(numUniqueUser.values()),
        'anomalyratio': list(anomalyRatio.values()),
        'useragent': list(useragent.values())
    })

    non_bot_fig = np.histogram(sorted(list(similarityResultsUser.values())), bins=40, density=False)

    simUserDf = simUserDf.sort_values(by='score', ascending=False)
    return simUserDf


simUserDf = getScoreDf(groupByIPfiltered)
simUserDf.to_csv(outfolder + "non_bot_graph_threshold_scores.csv", index=False)

groupByIPbot = [x for _, x in bots.groupby("ip")]
highUserSet = set()
for group in groupByIPbot:
    if group["request"].nunique(dropna = True) > 9:
        highUserSet.add(group["ip"].iloc[0])
groupByIPfilteredbot = list(filter(lambda x:x["ip"].iloc[0] in highUserSet, groupByIPbot))

botUserDf = getScoreDf(groupByIPfilteredbot)
botUserDf.to_csv(outfolder + "bot_graph_threshold_scores.csv", index=False)

groupByIPAll = [x for _, x in fullData.groupby("ip")]
highUserSet = set()
for group in groupByIPAll:
    if group["request"].nunique(dropna = True) > 9:
        highUserSet.add(group["ip"].iloc[0])
groupByIPfilteredAll = list(filter(lambda x:x["ip"].iloc[0] in highUserSet, groupByIPAll))

allUserDf = getScoreDf(groupByIPfilteredAll)
allUserDf = allUserDf[allUserDf["score"] >= 2]
allUserDf.to_csv(outfolder + "all_graph_threshold_scores.csv", index=False)


dt = StandardScaler().fit(np.array(allUserDf['score']).astype(float).reshape(-1, 1))
allUserDf['normalizedScores'] = dt.transform(np.array(allUserDf['score']).astype(float).reshape(-1, 1))
allUserDf.sort_values('score', ascending = False)

for index, user in allUserDf.iterrows():
    print(user['score'], user['useragent'])