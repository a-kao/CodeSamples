#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import re
import bisect
import random
import abc
from cStringIO import StringIO
# TODO: Feel free to import any Python standard modules as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    verbose = False
    httpVerbose = False
    httpObjectSizeLogger = False

    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        self.geoIPList = list()
        self.rulesList = list()
        self.logRules = list()
        self.httpDict = {}
        self.httpRules = list()


        self.preprocess(config['rule'])
        self.rulesList.reverse()

        self.lossRate = None
        if 'loss' in config.keys():
            self.lossRate = float(config['loss'])/float(100)
            if Firewall.verbose: print "Loss mode enabled: dropping packets with p = " + str(self.lossRate) + "\n"
        if Firewall.verbose: print "Logging http object sizes in file objectSizes.txt"

    def handle_timer(self):
        # TODO: For the timer feature, refer to bypass.py
        pass

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        #If loss mode enabled, check if packet should be dropped due to random chance
        if self.lossRate != None:
            if random.random() <= self.lossRate:
                if Firewall.verbose: print "randomly dropping packet due to configured mode\n"
                return

        #Parse the packet
        pktInfo = Utilities.parsePacket(pkt, pkt_dir, self.geoIPList)

        #If not a valid packet, drop
        if pktInfo.valid == False:
            return

        #Go through rules list
        forward = True
        match = False
        lastRuleMatched = None

        for rule in self.rulesList:
            ruleType = rule.getType()
            verdict = Constants.PASS

            if ruleType == Constants.STATELESS_IP_RULE:
                match, verdict = rule.isMatch(pktInfo.protocol, pktInfo.extIP, pktInfo.country, pktInfo.extPort)
            elif ruleType == Constants.STATELESS_DNS_RULE and pktInfo.hasDNSInfo:
                match, verdict = rule.isMatch(pktInfo.domainName)
            elif ruleType == Constants.STATEFUL_IP_RULE:
                match, verdict = rule.isMatch(pktInfo.protocol, pktInfo.extIP, pktInfo.extPort)
            elif ruleType == Constants.STATEFUL_DNS_RULE and pktInfo.hasDNSInfo:
                match, verdict = rule.isMatch(pktInfo.domainName)

            if match:
                forward = verdict
                lastRuleMatched = rule
                break

        #Handle logging; don't log info if packet is going to be dropped
        if forward:
            #log only if it is an http packet
            if pktInfo.protocol == Constants.TCP and pktInfo.extPort == Constants.HTTP_PORT_NUM:
                if self.handleHTTPPacket(pktInfo, pkt): return
                

        #Handle "normal" rule side-effects
        responsePkt = None
        if match:
            ruleType = lastRuleMatched.getType()
            if ruleType == Constants.STATEFUL_IP_RULE:
                if pktInfo.seqno == None:
                    return
                responsePkt = Utilities.generateTCPResetPkt(pktInfo.dstIP, pktInfo.dstPort, pktInfo.srcIP, pktInfo.srcPort, pktInfo.seqno)
                responsePkt = Utilities.appendIPHeader(pktInfo.dstIP, pktInfo.srcIP, Constants.TCP, responsePkt)
            elif ruleType == Constants.STATEFUL_DNS_RULE:
                if pktInfo.domainName == None:
                    return
                if pktInfo.hasDNSInfo and pktInfo.qType == 1:
                    if Firewall.verbose: print "Generating dns redirect packet"
                    responsePkt = Utilities.generateDNSRedirectPkt(pktInfo.domainName, pktInfo.dnsMessageID, pktInfo.dnsQuestion)
                    responsePkt = Utilities.appendUDPHeader(pktInfo.dstIP, pktInfo.srcIP, pktInfo.dstPort, pktInfo.srcPort, responsePkt)
                    responsePkt = Utilities.appendIPHeader(pktInfo.dstIP, pktInfo.srcIP, Constants.UDP, responsePkt)
        
        #Send response packet if exists
        if responsePkt != None:
            if pkt_dir:
                self.iface_int.send_ip_packet(responsePkt)
            else:
                self.iface_ext.send_ip_packet(responsePkt)
            if Firewall.verbose: print "response packet sent\n"

        #Send original packet if needed
        if forward:
            if pkt_dir:
                self.iface_ext.send_ip_packet(pkt)
                if Firewall.verbose: print "orig packet sent\n"
            else:
                self.iface_int.send_ip_packet(pkt)
                if Firewall.verbose: print "orig packet received\n"

            if Firewall.verbose:
                line = None
                if lastRuleMatched != None:
                    line = lastRuleMatched.line
                if Firewall.verbose: print "Last Matched Rule: " + str(line) + "\n"
            return

        if Firewall.verbose: print "packet dropped\n"
        if Firewall.verbose:
            line = None
            if lastRuleMatched != None:
                line = lastRuleMatched.line
            if Firewall.verbose: print "Last Matched Rule: " + str(line) + "\n"

    def preprocess(self, rulesFilename):
        self.loadGeoDB()
        self.loadRules(rulesFilename)

    def loadGeoDB(self):
        f = open('geoipdb.txt')
        for line in f:
            data = line.split()
            self.geoIPList.append(GeoIP(data[0], data[1], data[2]))

    def loadRules(self, rulesFilename):
        f = open(rulesFilename)
        for line in f:
            line = line.rstrip()
            if line == "" or line[0] == "%":
                continue
            rule = Rule.createRule(line)
            if rule.getType() == Constants.STATEFUL_LOG_RULE:
                self.logRules.append(rule)
            elif rule.getType() == Constants.STATLESS_HTTP_DENY_RULE:
                self.httpRules.append(rule)
            else:
                self.rulesList.append(rule)
    
    #bool return type: True - Drop Packet; False - Keep packet 
    def handleHTTPPacket(self, pktInfo, pkt):
        #if syn flag is set
        if pktInfo.tcpFlags & 0x02 == 0x02:
            if pktInfo.pktDir:
                if Firewall.httpVerbose: print "received outgoing syn, creating http connection entry"
                self.httpDict[(pktInfo.extIP, pktInfo.intPort)] = HTTPConnectionInfo(pktInfo.extIP, pktInfo.intPort, pktInfo.seqno)
            else:
                #received incoming syn pkt before outgoing syn, pass packet
                if (pktInfo.extIP,pktInfo.intPort) not in self.httpDict.keys():
                    if Firewall.httpVerbose: print "received incoming syn before outgoing, passing packet"
                    return False
                if Firewall.httpVerbose: print "3-way syn detected"
                self.httpDict[(pktInfo.extIP,pktInfo.intPort)].setIncomingISN(pktInfo.seqno)
        else:
            #If don't have connection record (and packet is not syn), pass the packet
            if (pktInfo.extIP, pktInfo.intPort) not in self.httpDict.keys():
                if Firewall.httpVerbose: print "don't have connection record, passing packet"
                return False

            connectionInfo = self.httpDict[(pktInfo.extIP, pktInfo.intPort)]
        
            #If FIN, no additional responses are possible. Therefore delete entry
            if (pktInfo.tcpFlags & 0x01 == 0x01):
                if pktInfo.pktDir:
                    if Firewall.httpVerbose: print "outgoing fin detected"
                    connectionInfo.expOutSeqno += 1
                else:
                    if Firewall.httpVerbose: print "inc fin detected"
                    del self.httpDict[(pktInfo.extIP, pktInfo.intPort)]
                return False
        
            #If reset is detected, delete the entry
            if pktInfo.tcpFlags & 0x04 == 0x04:
                if Firewall.httpVerbose: print "reset packet detected, deleting entry"
                del self.httpDict[(pktInfo.extIP, pktInfo.intPort)]
                return False
        
            #If it is a pure ack, pass the packet
            if pktInfo.applicationPayloadLength == 0 and pktInfo.tcpFlags & 0x10 == 0x10:
                if Firewall.httpVerbose: print "pure ack detected, passing"
                return False
            
            #If denying HTTP, drop the packet
            if connectionInfo.denyHTTP:
                if Firewall.httpVerbose: "denying http for this connection, dropping packet"
                return True
            
            #If connection not ready, pass the packet
            if connectionInfo.TCPConnectionState != Constants.READY:
                if Firewall.httpVerbose: print "connection not ready, passing packet"
                return False
        
            #If duplicate packet, pass the packet
            if connectionInfo.isDuplicatePacket(pktInfo):
                if Firewall.httpVerbose: print "is dup packet, passing"
                return False
        
            #If packet is outgoing and firewall not listening for requests, pass the packet
            if pktInfo.pktDir and connectionInfo.HTTPConnectionState != Constants.LISTENING_FOR_REQUESTS:
                if Firewall.httpVerbose: print "not listening for requests, pass packet"
                connectionInfo.expOutSeqno += pktInfo.applicationPayloadLength
                return False
            
            #If packet is incoming and firewall not listening for responses, pass the packet
            if not pktInfo.pktDir and connectionInfo.HTTPConnectionState != Constants.LISTENING_FOR_RESPONSES:
                if Firewall.httpVerbose: print "not listening for responses, passing packet"
                connectionInfo.expIncSeqno += pktInfo.applicationPayloadLength
                return False

            #If packet is not in order, drop the packet
            if not connectionInfo.isPacketInOrder(pktInfo):
                if Firewall.httpVerbose: print "packet not in order, dropping"
                return True

            #Update
            connectionInfo.update(pkt, pktInfo)
            
            #Check if we should deny http
            if connectionInfo.logInfo.hasRequestInfo:
                for rule in self.httpRules:
                    if rule.isMatch(connectionInfo.logInfo.hostName, connectionInfo.logInfo.path):
                        if Firewall.httpVerbose: print "found match for deny http"
                        connectionInfo.denyHTTP = True

                        if pktInfo.pktDir:
                            if Firewall.httpVerbose: print "sending http 404 response packet"
                            responsePacket = Utilities.appendTCPHeader(pktInfo.dstIP, pktInfo.srcIP, pktInfo.dstPort, pktInfo.srcPort, connectionInfo.expIncSeqno + connectionInfo.incISN, 0, 0x08, 0xFFFF, Constants.HTTP_NOT_FOUND_CLOSE)
                            responsePacket = Utilities.appendIPHeader(pktInfo.dstIP, pktInfo.srcIP, Constants.TCP, responsePacket)
                            self.iface_int.send_ip_packet(responsePacket)
                            if Firewall.httpVerbose: print "sending http deny response pkt"
                            return True

            #Determine if log should be written to
            writeToLog = False
            if connectionInfo.logInfo.canWriteToLog():
                if Firewall.httpVerbose: print "can write to log"
                for rule in self.logRules:
                    if rule.isMatch(connectionInfo.logInfo.hostName):
                        writeToLog = True
                        break

            if writeToLog:
                if Firewall.httpVerbose: print "writing to log"
                f = open('http.log', 'a')
                f.write(connectionInfo.logInfo.write() + "\n")
                f.flush()
                
            if Firewall.httpObjectSizeLogger and str(connectionInfo.logInfo.statusCode) == "200":
                g = open('objectSize.txt', 'a')
                g.write(str(connectionInfo.logInfo.objectSize) + "\n")
                g.flush()
            if connectionInfo.logInfo.canWriteToLog(): connectionInfo.logInfo.reset()
        if Firewall.httpVerbose: print "\n"
        return False
            
class HTTPConnectionInfo:
    def __init__(self, extIP, intPort, outISN):
        self.extIP = extIP
        self.intPort = intPort
        
        self.TCPConnectionState = Constants.WAITING_FOR_INC_SYN
        self.HTTPConnectionState = Constants.WAITING_FOR_HANDSHAKE
        
        self.outISN = outISN & 0xFFFFFFFF

        self.expIncSeqno = 1
        self.expOutSeqno = 1

        self.outFSV = Constants.NO_MATCH
        self.incFSV = Constants.NO_MATCH

        self.requestHeader = ""
        self.responseHeader = ""

        self.logInfo = HTTPRequestResponse(self.extIP, self.intPort)
        
        self.denyHTTP = False
    
    def setIncomingISN(self, isn):
        self.incISN = isn & 0xFFFFFFFF
        self.TCPConnectionState = Constants.READY
        self.HTTPConnectionState = Constants.LISTENING_FOR_REQUESTS
    
    #If false, drop the packet. Doesn't mean we haven't already seen this packet before
    def isPacketInOrder(self, pktInfo):
        if pktInfo.pktDir:
            return pktInfo.seqno <= self.expOutSeqno + self.outISN
        else:
            return pktInfo.seqno <= self.expIncSeqno + self.incISN
        
    def isDuplicatePacket(self, pktInfo):
        if pktInfo.pktDir:
            return pktInfo.seqno < self.expOutSeqno + self.outISN
        else:
            return pktInfo.seqno < self.expIncSeqno + self.incISN
    
    def update(self, pkt, pktInfo):
        newHeaderData = None
        newFSV = None
        remBodyLength = None

        #Parse the packet
        if Firewall.httpVerbose: print "parsing packet"
        if pktInfo.pktDir:
            newHeaderData, newFSV, remBodyLength = Utilities.parseHTTP(pktInfo, pkt, self.outFSV)
        else:
            newHeaderData, newFSV, remBodyLength = Utilities.parseHTTP(pktInfo, pkt, self.incFSV)

        #Update connection information
        if pktInfo.pktDir:
            self.expOutSeqno += pktInfo.applicationPayloadLength 
            self.requestHeader = self.requestHeader + newHeaderData
            self.outFSV = newFSV
        else:
            self.expIncSeqno += pktInfo.applicationPayloadLength 
            self.responseHeader = self.responseHeader + newHeaderData
            self.incFSV = newFSV

        #Determine if http connection status changes
        if self.outFSV == Constants.SECOND_N:
            if Firewall.httpVerbose: print "changing connection status to listening for responses"
            HTTPConnectionInfo.parseHTTPRequest(self.requestHeader, self.logInfo)
            self.outFSV = Constants.NO_MATCH
            self.requestHeader = ""
            self.HTTPConnectionState = Constants.LISTENING_FOR_RESPONSES
        elif self.incFSV == Constants.SECOND_N:
            if Firewall.httpVerbose: print "changing connection status to listening for requests"
            HTTPConnectionInfo.parseHTTPResponse(self.responseHeader, self.logInfo)
            self.incFSV = Constants.NO_MATCH
            self.responseHeader = ""
            self.HTTPConnectionState = Constants.LISTENING_FOR_REQUESTS
            
    @staticmethod
    def parseHTTPRequest(requestHeader, logInfo):
        hostName = None

        headerLines = requestHeader.split('\n')

        #Process request line
        requestLineAttributes = headerLines[0].replace("\r", "")
        requestLineAttributes = requestLineAttributes.split()
        method = requestLineAttributes[0]
        path = requestLineAttributes[1]
        version = requestLineAttributes[2]
        
        #Process request fields
        for line in headerLines[1:]:

            line = line.replace("\r", "")
            partitioned = line.partition(": ")

            if partitioned[0].lower() == "host":
                hostName = partitioned[2]
                break
        
        if hostName == None: hostName = socket.inet_ntoa(struct.pack("@L", logInfo.extIP))
        logInfo.insertRequestInfo(method, path, version, hostName)

    @staticmethod
    def parseHTTPResponse(responseHeader, logInfo):
        objectSize = None

        headerLines = responseHeader.split('\n')
        
        #Process response line
        responseLineAttributes = headerLines[0].replace("\r", "")
        responseLineAttributes = responseLineAttributes.split()
        status = responseLineAttributes[1]
        
        #Process request fields
        for line in headerLines[1:]:

            line = line.replace("\r", "")
            partitioned = line.partition(": ")
    
            if partitioned[0].lower() == "content-length":
                objectSize = partitioned[2]
            
            if objectSize != None:
                break
        
        if objectSize == None:
            objectSize = "-1"

        logInfo.insertResponseInfo(status, objectSize)

class HTTPRequestResponse:
    def __init__(self, extIP, intPort):
        self.extIP = extIP
        self.intPort = intPort
        
        self.hasRequestInfo = False
        self.hasResponseInfo = False
        
    def insertRequestInfo(self, method, path, version, hostName):
        self.method = method
        self.version = version
        self.hostName = hostName
        self.path = path

        self.hasRequestInfo = True
    
    def insertResponseInfo(self, statusCode, objectSize):
        self.statusCode = statusCode
        self.objectSize = objectSize

        self.hasResponseInfo = True
    
    def canWriteToLog(self):
        return self.hasRequestInfo and self.hasResponseInfo
    
    #Wrap all of these in string after testing complete to avoid crashes
    def write(self):
        if Firewall.httpVerbose: print str(self.hostName) + " " + str(self.method) + " " + str(self.path) + " " + str(self.version) + " " + str(self.statusCode) + " " + str(self.objectSize) + "\r"
        return str(self.hostName) + " " + str(self.method) + " " + str(self.path) + " " + str(self.version) + " " + str(self.statusCode) + " " + str(self.objectSize) + "\r"
    
    def reset(self):
        self.method = None
        self.version = None
        self.hostName = None

        self.hasRequestInfo = False
        
        self.statusCode = None
        self.path = None
        self.objectSize = None
        
        self.hasResponseInfo = False

        
class GeoIP:
    def __init__(self, ipStart, ipEnd, country):
        self.key = struct.unpack('!L', socket.inet_aton(ipStart))[0]
        self.ipStart = ipStart
        self.ipEnd = ipEnd
        self.country = country

    def __lt__(self, other):
        if self.key < other:
            return True
        return False
    def __le__(self, other):
        if self.key <= other:
            return True
        return False
    def __eq__(self, other):
        if self.key == other:
            return True
        return False
    def __ne__(self, other):
        if self.key != other:
            return True
        return False
    def __gt__(self, other):
        if self.key > other:
            return True
        return False
    def __ge__(self, other):
        if self.key >= other:
            return True
        return False

class Constants:
    #Rule Types
    BASE_RULE = 0
    STATELESS_IP_RULE = 1
    STATELESS_DNS_RULE = 2
    STATEFUL_IP_RULE = 3
    STATEFUL_DNS_RULE = 4
    STATEFUL_LOG_RULE = 5
    STATLESS_HTTP_DENY_RULE = 6
    
    #Protocol Types
    UDP = 17
    TCP = 6
    ICMP = 1

    DNS_PORT_NUM = 53
    HTTP_PORT_NUM = 80
    
    #Verdicts
    DROP = 0
    PASS = 1

    #Redirect IPs
    DNS_REDIRECT = 2850369901
    
    #HTTP Parser Finite States
    NO_MATCH = 0
    FIRST_R = 1
    FIRST_N = 2
    SECOND_R = 3
    SECOND_N = 4
    
    #TCP Connection States
    WAITING_FOR_INC_SYN = 0
    READY = 1

    #HTTP Connection States
    WAITING_FOR_HANDSHAKE = 0
    LISTENING_FOR_REQUESTS = 1
    LISTENING_FOR_RESPONSES = 2
    
    #HTTP Response (bytes)
    
    #404 not found, connection: close
    HTTP_NOT_FOUND_CLOSE = "\x48\x54\x54\x50\x2f\x31\x2e\x31\x20\x34\x30\x34\x20\x4e\x6f\x74\x20\x46\x6f\x75\x6e\x64\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x63\x6c\x6f\x73\x65\x0d\x0a\x0d\x0a"


class Rule:
    type = Constants.BASE_RULE
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def getType(self):
        return Rule.type

    @classmethod
    def createRule(cls, line):
        args = line.split()
        if "deny" == args[0].lower():
            if "tcp" == args[1].lower():
                return StatefulIPRule(args[2], args[3], line)
            elif "dns" == args[1].lower():
                return StatefulDNSRule(args[2], line)
            elif "http" == args[1].lower():
                return StatelessHTTPDenyRule(args[2], args[3], line)
        elif "log" == args[0].lower():
            return StatefulLogRule(args[2], line)
        elif "dns" == args[1].lower():
            return StatelessDNSRule(args[0], args[2], line)
        else:
            return StatelessIpRule(args[0], args[1], args[2], args[3], line)

class StatelessIpRule(Rule):
    type = Constants.STATELESS_IP_RULE

    def __init__(self, verdict, protocol, externalIP, externalPort, line = None):
        self.line = line

        if verdict.lower() == "pass":
            self.verdict = Constants.PASS
        else:
            self.verdict = Constants.DROP

        if protocol == None:
            self.protocol = None 
        elif protocol.lower() == "tcp":
            self.protocol = Constants.TCP
        elif protocol.lower() == "udp":
            self.protocol = Constants.UDP
        elif protocol.lower() == "icmp": #changed this to be more explicit v2
            self.protocol = Constants.ICMP

        if externalIP == None:
            self.country = None
            self.ip = None
            self.mask = None
        elif externalIP.lower() == "any":
            self.country = None
            self.ip = 0
            self.mask = 0
        elif len(externalIP) == 2:
            self.country = externalIP
            self.ip = None
            self.mask = None
        else:
            self.country = None
            prefixAndSlash = externalIP.split("/")
            self.ip = struct.unpack('!L', socket.inet_aton(prefixAndSlash[0]))[0]
            self.mask = 0xFFFFFFFF
            if len(prefixAndSlash) != 1:
                self.mask = (self.mask << (32 - int(prefixAndSlash[1]))) & 0xFFFFFFFF

        if externalPort == None:
            self.port = None
        elif externalPort == "any":
            self.port = [1, 65535]
        else:
            portRange = externalPort.split("-")
            self.port = [int(portRange[0]), int(portRange[0])]
            if len(portRange) != 1:
                self.port[1] = int(portRange[1])

    def isMatch(self, protocol, extIP, country, extPort):
        if self.protocol != protocol:
            return False, None
        if self.country != None:
            if country != None and self.country.lower() != country.lower():
                return False, None
        else:
            if self.ip != extIP & self.mask:
                return False, None
        if extPort < self.port[0] or extPort > self.port[1]:
            return False, None
        return True, self.verdict

    def getType(self):
        return StatelessIpRule.type

class StatelessDNSRule(Rule):
    type = Constants.STATELESS_DNS_RULE

    def __init__(self, verdict, domainName, line = None):
        self.line = line

        if verdict.lower() == "pass":
            self.verdict = Constants.PASS
        else:
            self.verdict = Constants.DROP

        if "*" in domainName:
            self.domainMatcher = re.compile(domainName.split("*")[1] + "$", re.IGNORECASE)
        else:
            self.domainMatcher = re.compile("^" + domainName +"$", re.IGNORECASE)

    def isMatch(self, domainName):
        if domainName == None: return False, None

        match = self.domainMatcher.search(domainName) != None
        return match, self.verdict

    def getType(self):
        return StatelessDNSRule.type

class StatefulIPRule(Rule):
    type = Constants.STATEFUL_IP_RULE

    def __init__(self, ip, port, line = None):
        self.line = line
        if ip.lower() == "any":
            self.country = None
            self.ip = 0
            self.mask = 0
        else:
            prefixAndSlash = ip.split("/")
            self.ip = struct.unpack('!L', socket.inet_aton(prefixAndSlash[0]))[0]
            self.mask = 0xFFFFFFFF
            if len(prefixAndSlash) != 1:
                self.mask = (self.mask << (32 - int(prefixAndSlash[1]))) & 0xFFFFFFFF

        if port == "any":
            self.port = [1, 65535]
        else:
            portRange = port.split("-")
            self.port = [int(portRange[0]), int(portRange[0])]
            if len(portRange) != 1:
                self.port[1] = int(portRange[1])

    def isMatch(self, protocol, inputIP, inputPort):
        if Constants.TCP != protocol:
            return False, None

        if self.ip != inputIP & self.mask:
            return False, None

        if inputPort < self.port[0] or inputPort > self.port[1]:
            return False, None

        return True, Constants.DROP
    
    def getType(self):
        return StatefulIPRule.type

class StatefulDNSRule(Rule):
    type = Constants.STATEFUL_DNS_RULE

    def __init__(self, domainName, line = None):
        self.line = line

        if "*" in domainName:
            self.domainMatcher = re.compile(domainName.split("*")[1] + "$", re.IGNORECASE)
        else:
            self.domainMatcher = re.compile("^" + domainName +"$", re.IGNORECASE)

    def isMatch(self, domainName):
        if domainName == None: return False, None

        match = self.domainMatcher.search(domainName) != None
        return match, Constants.DROP

    def getType(self):
        return StatefulDNSRule.type

class StatefulLogRule(Rule):
    type = Constants.STATEFUL_LOG_RULE

    def __init__(self, hostName, line = None):
        self.line = line

        if "*" in hostName:
            self.hostMatcher = re.compile(hostName.split("*")[1] + "$", re.IGNORECASE)
        else:
            self.hostMatcher = re.compile("^" + hostName +"$", re.IGNORECASE)

    def isMatch(self, hostName):
        if hostName == None: return False, None

        match = self.hostMatcher.search(hostName) != None
        return match

    def getType(self):
        return StatefulLogRule.type

class StatelessHTTPDenyRule(Rule):
    type = Constants.STATLESS_HTTP_DENY_RULE

    def __init__(self, hostName, path, line = None):
        self.line = line

        if "*" in hostName:
            self.hostMatcher = re.compile(hostName.split("*")[1] + "$", re.IGNORECASE)
        else:
            self.hostMatcher = re.compile("^" + hostName +"$", re.IGNORECASE)
        
        self.pathMatcher = re.compile(path)

    def isMatch(self, hostName, path):
        if hostName == None: return False, None

        match = self.hostMatcher.search(hostName) != None and self.pathMatcher.search(path) != None
        return match

    def getType(self):
        return StatelessHTTPDenyRule.type

class PacketInfo:
    def __init__(self, valid):
        self.valid = valid

        self.hasDNSInfo = False
        self.hasTransportInfo = False
        self.hasIPInfo = False
        self.hasHTTPInfo = False
    
    def insertHTTPData(self):
        self.hasHTTPInfo = True
    
    def insertDNSData(self, domainName, dnsQuestion, dnsMessageID, qdCount, qType, qClass):
        self.domainName = domainName
        self.dnsQuestion = dnsQuestion
        self.dnsMessageID = dnsMessageID
        self.qdCount = qdCount
        self.qType = qType
        self.qClass = qClass

        self.hasDNSInfo = True
        
    def insertIPData(self, srcIP, dstIP, protocol, ihl):
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.protocol = protocol
        self.ihl = ihl

        self.hasIPInfo = True

    def insertTransportData(self, srcPort, dstPort, seqno, transportDataOffset, appPayloadLen, flags):
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.seqno = seqno
        self.transportDataOffset = transportDataOffset
        self.applicationPayloadLength = appPayloadLen
        self.tcpFlags = flags

        self.hasTransportInfo = True
        
    def insertOrd(self, extIP, extPort, intIP, intPort):
        self.extIP = extIP
        self.extPort = extPort
        
        self.intIP = intIP
        self.intPort = intPort

    def insertCountry(self, country):
        self.country = country
        if self.country != None: self.country = country.country
        
    def insertDirection(self, pktDir):
        self.pktDir = pktDir

    def destroyDNSData(self):
        self.domainName = None
        self.dnsQuestion = None
        self.dnsMessageID = None

        self.hasDNSInfo = False

class Utilities:
    @staticmethod
    def find_le(a, x):
        i = bisect.bisect_right(a, x)
        if i <= len(a) and i > 0: 
            if x >= a[i-1].ipStart and x <= a[i-1].ipEnd:
                return a[i-1]
        return None

    @staticmethod
    def parseIP(pktData, pktInfo):
        if len(pktData) < 20: return PacketInfo(False)

        ihl = struct.unpack_from("!B", pktData, 0)[0] & 0x0F
        tl = struct.unpack_from("!H", pktData, 2)[0]
        protocol = struct.unpack_from("!B", pktData, 9)[0]
        srcIP = struct.unpack_from("!L", pktData, 12)[0]
        dstIP = struct.unpack_from("!L", pktData, 16)[0]

        if len(pktData) != tl: return PacketInfo(False)

        pktInfo.insertIPData(srcIP, dstIP, protocol, ihl)
        return pktInfo

    @staticmethod
    def parseTransportLayer(pktData, pktInfo):
        offset = pktInfo.ihl * 4
        protocol = pktInfo.protocol

        srcPort = None
        dstPort = None
        dataOffset = 0
        seqno = None
        flags = None

        if pktInfo.protocol == Constants.TCP:
            if len(pktData) < offset + 20: return PacketInfo(False)
            srcPort = struct.unpack_from("!H", pktData, offset)[0]
            dstPort = struct.unpack_from("!H", pktData, offset+2)[0]
            seqno = struct.unpack_from("!L", pktData, offset+4)[0]
            dataOffset = (struct.unpack_from("!B", pktData, offset + 12)[0] >> 4)*4
            flags = struct.unpack_from("!B", pktData, offset+13)[0]
        elif protocol == Constants.UDP:
            if len(pktData) < offset + 8: return PacketInfo(False)
            srcPort = struct.unpack_from("!H", pktData, offset)[0]
            dstPort = struct.unpack_from("!H", pktData, offset+2)[0]
            dataOffset = 8 #data offset should be the size of the header v2
        elif protocol == Constants.ICMP:
            if len(pktData) < offset + 8: return PacketInfo(False)
            srcPort = struct.unpack_from("!B", pktData, offset)[0] >> 4
            dstPort = srcPort
            dataOffset = 8 #data offset should be the size of the header v2

        if len(pktData) < offset + dataOffset: return PacketInfo(False)

        pktInfo.insertTransportData(srcPort, dstPort, seqno, dataOffset, len(pktData) - (offset + dataOffset), flags)

        return pktInfo

    @staticmethod
    def parseDNSQuery(pktData, pktInfo):
        offset = pktInfo.transportDataOffset
        
        if len(pktData) < offset + 12: return PacketInfo(False)

        messageID = struct.unpack_from("!H", pktData, offset)[0]
        qdCount = struct.unpack_from("!H", pktData, offset + 4)[0]

        valid = False
        qName = ""
        i= 12

        while i + offset < len(pktData):
            length = struct.unpack_from("!B", pktData, offset + i)[0]
            if length == 0:
                qName = qName[0:len(qName)-1]
                valid = True
                break
            i += 1
            for j in range(length):
                qName = qName + struct.unpack_from("!c", pktData, offset+i)[0]
                i+= 1
                if i + offset >= len(pktData) + 1:  
                    break
            qName = qName + "."

        if len(pktData) < offset + i + 4: return PacketInfo(False)

        qType = struct.unpack_from("!H", pktData, offset+i+1)[0]
        qClass = struct.unpack_from("!H", pktData, offset+i+3)[0]
        dnsQuestion = pktData[12 + offset:offset+i+5]

        pktInfo.insertDNSData(qName, dnsQuestion, messageID, qdCount, qType, qClass)
        pktInfo.valid = valid
        return pktInfo

    @staticmethod
    def parsePacket(pkt, pkt_dir, geoIPList):
        if Firewall.verbose: print "outgoing: " + str(pkt_dir == PKT_DIR_OUTGOING)
        pktInfo = PacketInfo(True)
        
        #Insert direction
        pktInfo.insertDirection(pkt_dir)

        #Parsing IP Layer
        if Firewall.verbose: print "parsing ip layer..."
        pktInfo = Utilities.parseIP(pkt, pktInfo)
        if not pktInfo.valid:
            if Firewall.verbose: print "invalid ip header\n" 
            return PacketInfo(False)

        #Parsing Transport Layer
        if Firewall.verbose: print "parsing transport layer..."
        pktInfo = Utilities.parseTransportLayer(pkt, pktInfo)
        if not pktInfo.valid:
            if Firewall.verbose: print "invalid link layer header\n" 
            return PacketInfo(False)

        #Determine external address
        if pkt_dir:
            pktInfo.insertOrd(pktInfo.dstIP, pktInfo.dstPort, pktInfo.srcIP, pktInfo.srcPort)
        else:
            pktInfo.insertOrd(pktInfo.srcIP, pktInfo.srcPort, pktInfo.dstIP, pktInfo.dstPort)
            
        #Insert Country
        pktInfo.insertCountry(Utilities.find_le(geoIPList, pktInfo.extIP))
        if pktInfo.country == None:
            if Firewall.verbose: print "no country found\n"

        #Handle DNS Packets
        if pkt_dir and pktInfo.protocol == Constants.UDP and pktInfo.extPort == Constants.DNS_PORT_NUM:
            if Firewall.verbose: print "parsing dns query..."
            pktInfo = Utilities.parseDNSQuery(pkt, pktInfo)
            if Firewall.verbose: print "DNS Complete: " + str(pktInfo.hasDNSInfo)
            if Firewall.verbose: print "Domain Name parsed: " + pktInfo.domainName + "\n"

            #If packet is malformed, drop it
            if not pktInfo.valid:
                if Firewall.verbose: print "invalid dns query header\n" 
                return PacketInfo(False)

            #If the below conditions hold, that means the query is valid but is not a match(i.e. more than 1 question)
            #thus, pass it on but without the dns specific information
            if not Utilities.isValidDNS(pktInfo):
                pktInfo.destroyDNSData()

        #Handle HTTP Packets
        if pktInfo.protocol == Constants.TCP and pktInfo.extPort == Constants.HTTP_PORT_NUM:
            pktInfo.insertHTTPData()

        return pktInfo

    @staticmethod
    def isValidDNS(pktInfo):
        return pktInfo.protocol == Constants.UDP and pktInfo.extPort == Constants.DNS_PORT_NUM and pktInfo.qdCount == 1 and (pktInfo.qType == 1 or pktInfo.qType == 28) and pktInfo.qClass == 1

    @staticmethod
    def generateLinkChecksum(srcIP, dstIP, pktData, protocol):
        length = len(pktData)
        bytesLeft = length
        s = 0
        while bytesLeft > 1:
            s += struct.unpack_from("!H", pktData, length - bytesLeft)[0]
            bytesLeft = bytesLeft - 2

        if bytesLeft == 1:
            s += (struct.unpack_from("!B", pktData, length - 1)[0] << 8) & 0xFF00
        
        s += srcIP&0xFFFF #get bottom 16 bits
        s += srcIP>>16  #get top 16 bits
        s += dstIP&0xFFFF #get bottom 16 bits
        s += dstIP>>16  #get top 16 bits
        s += length  #add length
        s += protocol  #add protocol
        
        s = (s >> 16) + (s & 0xFFFF) #keep last 16 bits and add carries
        s += (s >> 16)  #add carries again
        s += (s >> 16)  #and again
        
        s = ~s  #take ones complement
        return s & 0xFFFF #convert to unsigned

    @staticmethod
    def generateIPChecksum(pkt, ipHeaderLengthBytes):
        s = 0
        bytesLeft = ipHeaderLengthBytes
        while bytesLeft > 1:
            s += struct.unpack_from("!H", pkt, ipHeaderLengthBytes - bytesLeft)[0]
            bytesLeft -= 2
        
        s = (s >> 16) + (s & 0xFFFF)
        s += s>>16
        answer = ~s
        return answer & 0xFFFF

    @staticmethod
    def generateTCPResetPkt(srcIP, srcPort, dstIP, dstPort, seqno):
        tcpBytes = struct.pack("!HHIIBBHHH", srcPort, dstPort, 0x00000000, seqno + 1, 0x50, 0x14, 0x0000, 0x0000, 0x0000)
        checksum = Utilities.generateLinkChecksum(srcIP, dstIP, tcpBytes, Constants.TCP)
        tcpBytes = tcpBytes[0:16] + struct.pack("!H", checksum) + tcpBytes[18:20]
        return tcpBytes
    
    @staticmethod
    def generateDNSRedirectPkt(domainName, messageID, dnsQuestion):
        if domainName == None:
            #return empty dns redirect if cannot construct valid dns packet
            return ""

        dnsHeader = struct.pack("!HBBHHHH", messageID, 0x80, 0x00, 0x0001, 0x0001, 0x0000, 0x0000)
        dnsAnswer = struct.pack("!HHHLHL", 0xc00c, 1, 1, 1, 0x0004, Constants.DNS_REDIRECT)

        return dnsHeader + dnsQuestion + dnsAnswer

    @staticmethod
    def appendUDPHeader(srcIP, dstIP, srcPort, dstPort, pktData):
        udpHeader = struct.pack("!HHHH", srcPort, dstPort, len(pktData) + 8, 0x0000)
        udpData = udpHeader + pktData
        return udpData

    @staticmethod
    def appendTCPHeader(srcIP, dstIP, srcPort, dstPort, seqno, ackno, flags, windowSize, pktData):
        tcpHeader = struct.pack("!HHLLBBHHH", srcPort, dstPort, seqno, ackno, 0x50, flags, windowSize, 0, 0)
        tcpPkt = tcpHeader + pktData
        checksum = Utilities.generateLinkChecksum(srcIP, dstIP, tcpPkt, Constants.TCP)
        tcpPkt = tcpPkt[0:16] + struct.pack("!H", checksum) + tcpPkt[18:]
        return tcpPkt
        
    @staticmethod
    #no options, ipv4
    def appendIPHeader(srcIP, dstIP, protocol, payload):
        header = struct.pack("!BBHLBBHLL", 0x45, 0x00, 20 + len(payload), 0, 64, protocol, 0, srcIP, dstIP)
        pkt = header + payload
        checksum = Utilities.generateIPChecksum(pkt, len(header))
        pkt = pkt[0:10] + struct.pack("!H", checksum) + pkt[12:]
        return pkt
    
    @staticmethod
    def parseHTTP(pktInfo, pkt, fsv):
        def update(char, curFSV):
            if char == '\n':
                if curFSV == Constants.NO_MATCH:
                    return Constants.FIRST_N
                if curFSV == Constants.FIRST_R:
                    return Constants.FIRST_N
                if curFSV == Constants.SECOND_R:
                    return Constants.SECOND_N
                if curFSV == Constants.FIRST_N:
                    return Constants.SECOND_N
            elif char == '\r':
                if curFSV == Constants.NO_MATCH:
                    return Constants.FIRST_R
                if curFSV == Constants.FIRST_N:
                    return Constants.SECOND_R
            
            return Constants.NO_MATCH

        offset = 4 * pktInfo.ihl + pktInfo.transportDataOffset
        curFSV = fsv
        fileStr = StringIO()
        char = None
        remBodyLength = None

        while offset < len(pkt):
            char = struct.unpack_from("!c", pkt, offset)[0]
            fileStr.write(char)
            curFSV = update(char, curFSV)
            offset += 1
            if curFSV == Constants.SECOND_N:
                remBodyLength = len(pkt) - offset - 1
                break

        return fileStr.getvalue(), curFSV, remBodyLength

    @staticmethod
    def byteify(bytesString):
        if len(bytesString)%2 == 1:
            print "Not divisible by 2, therefore not a valid packet"
            return
        i = 2
        stringify = ""
        for c in bytesString:
            if i == 2:
                i = 0
                stringify += "\\x"
            stringify = stringify + c
            i += 1
        return stringify         
                

                
                