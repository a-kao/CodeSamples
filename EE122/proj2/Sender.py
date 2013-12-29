import sys
import getopt
import time
import os

import Checksum
import BasicSender

'''
This is a skeleton sender class. Create a fantastic transport protocol here.
'''
class Sender(BasicSender.BasicSender):
    def __init__(self, dest, port, filename, debug=False):
        super(Sender, self).__init__(dest, port, filename, debug)
        self.filepath = filename
        self.windowBuffer = list()
        self.swindStart = 0
        self.swindEnd = -1
        self.dupAcks = 0
        self.verbose = True

    # Main sending loop.
    def start(self):
        self.startTime = time.time()
        msg_type = None
        complete = False
        while(not complete):
            while len(self.windowBuffer) <= 5 and msg_type != 'end':
                new_msg = self.infile.read(1400)
                self.swindEnd += 1

                if self.swindEnd == 0:
                    msg_type = 'start'
                elif new_msg == "":
                    msg_type = 'end'
                else:
                    msg_type = 'data'
    
                packet = self.make_packet(msg_type,self.swindEnd,new_msg)
                self.windowBuffer.append(bufferPacket(self.getCurrentTimeMillis(), self.swindEnd, packet))
                self.send(packet)
    
            response = None
            nextTimeout = 500 - (self.getCurrentTimeMillis() - self.windowBuffer[0].timeSent)
            if nextTimeout > 0:
                response = self.receive(nextTimeout/1000)
            else:
                response = self.receive(0)
            self.handle_response(response)
            
            if msg_type == 'end' and self.swindStart == self.swindEnd+1:
                complete = True
     
        self.endTime = time.time()
        self.infile.close()
        if self.verbose:
            self.printStatistics()

    def handle_response(self, response):
        if response == None:
            self.handle_timeout()
            return
        elif not Checksum.validate_checksum(response):
            return

        ackSeqno = self.getAckSeqno(response)
        if ackSeqno == -1:
            return

        if ackSeqno < self.swindStart:
            return
        elif ackSeqno == self.swindStart:
            self.handle_dup_ack(ackSeqno)
        elif ackSeqno <= self.swindEnd + 1:
            self.handle_new_ack(ackSeqno)

    def handle_timeout(self):
        for bufferedPacket in self.windowBuffer:
            bufferedPacket.timeSent = self.getCurrentTimeMillis()
            self.send(bufferedPacket.packet)
        self.dupAcks = 0

    def handle_new_ack(self, ackSeqno):
        del self.windowBuffer[0:ackSeqno-self.swindStart]
        self.swindStart = ackSeqno
        self.dupAcks = 0

    def handle_dup_ack(self, ackSeqno):
        self.dupAcks += 1
        if self.dupAcks >=3:
            self.send(self.windowBuffer[0])
        self.dupAcks = 0

    def log(self, msg):
        if self.debug:
            print msg

    def getCurrentTimeMillis(self):
        return time.time() * 1000

    def getAckSeqno(self, message):
        pieces = message.split('|')
        if pieces[0] != "ack":
            return -1
        return int(pieces[1])

    def printStatistics(self):
        elapsedTime = self.endTime - self.startTime
        fileSize = os.path.getsize(self.filepath)
        print("\nStatistics")
        print("==========================")
        print("Elapsed time: " + str(elapsedTime) + " seconds")
        print("File size: " + str(fileSize) + " bytes")
        print("Throughput: " + str(fileSize/elapsedTime) + " Bps")
        print("Packets: " + str(self.swindEnd) + "\n")

class bufferPacket:
    def __init__(self, timeSent, seqno, packet):
        self.timeSent = timeSent
        self.seqno = seqno
        self.packet = packet

'''
This will be run if you run this script from the command line. You should not
change any of this; the grader may rely on the behavior here to test your
submission.
'''
if __name__ == "__main__":
    def usage():
        print "BEARS-TP Sender"
        print "-f FILE | --file=FILE The file to transfer; if empty reads from STDIN"
        print "-p PORT | --port=PORT The destination port, defaults to 33122"
        print "-a ADDRESS | --address=ADDRESS The receiver address or hostname, defaults to localhost"
        print "-d | --debug Print debug messages"
        print "-h | --help Print this usage message"

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                               "f:p:a:d", ["file=", "port=", "address=", "debug="])
    except:
        usage()
        exit()

    port = 33122
    dest = "localhost"
    filename = None
    debug = False

    for o,a in opts:
        if o in ("-f", "--file="):
            filename = a
        elif o in ("-p", "--port="):
            port = int(a)
        elif o in ("-a", "--address="):
            dest = a
        elif o in ("-d", "--debug="):
            debug = True

    s = Sender(dest,port,filename,debug)
    try:
        s.start()
    except (KeyboardInterrupt, SystemExit):
        exit()
