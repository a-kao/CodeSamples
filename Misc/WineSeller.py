import pandas
from graph_tool.all import *
from collections import deque
import cProfile, pstats, StringIO
import getopt
import sys

def readFiles(filename):
    df = pandas.read_table(filename, header = None)
    df.columns = ['friends', 'wines']
    return df

def buildGraph(df):
    g = Graph()
    friendNameIntMap = {}
    friendIntNameMap = {}
    wineNameIntMap = {}
    wineIntNameMap = {}
    friendWineEdges = deque()
    vprop_name = g.new_vertex_property("string")
    eprop_weights = g.new_edge_property("int32_t")
    
    #create source and sink nodes
    source = g.add_vertex()
    vprop_name[source] = "source"
    sink = g.add_vertex()
    vprop_name[sink] = "sink"
    
    j = 0
    #create friend nodes
    for friendName in df['friends'].unique():
    
        #add friend node
        friend = g.add_vertex()
        vprop_name[friend] = friendName
        friendNameIntMap[friendName] = g.vertex_index[friend]
        friendIntNameMap[g.vertex_index[friend]] = friendName

        #add edge source - friend
        sofEdge = g.add_edge(source, friend)
        eprop_weights[sofEdge] = 3
        j += 1
    
    print "Total number of friends is: " + str(j)
    
    k = 0
    #create wine nodes
    for wineName in df['wines'].unique():
    
        #add wine node
        wine = g.add_vertex()
        vprop_name[wine] = wineName
        wineNameIntMap[wineName] = g.vertex_index[wine]
        wineIntNameMap[g.vertex_index[wine]] = wineName

        #add edge wine - sink
        wsiEdge = g.add_edge(wine, sink)
        eprop_weights[wsiEdge] = 1
        k += 1
    
    print "Total number of wines is: " + str(k)
    
    #create friend - wine edges
    friendCol = df['friends']
    wineCol = df['wines']
    for i in range(0, len(friendCol)):
        curFriendNode = friendNameIntMap[friendCol[i]]
        curWineNode = wineNameIntMap[wineCol[i]]

        curEdge = g.add_edge(curFriendNode, curWineNode)
        eprop_weights[curEdge] = 1

        friendWineEdges.append(curEdge)

    return g, source, sink, eprop_weights, friendWineEdges, friendIntNameMap, wineIntNameMap
    
def writeOutput(g, residuals, friendWineEdges, friendIntNameMap, wineIntNameMap):
    #write to file
    f = open('wineOutput.txt', 'w')
    
    i = 0
    while len(friendWineEdges) != 0:
        edge = friendWineEdges.popleft()
        if residuals[edge] == 0:
            friendName = friendIntNameMap[g.vertex_index[edge.source()]]
            wineName = wineIntNameMap[g.vertex_index[edge.target()]]
            f.write(friendName + " " + wineName + "\n")
            i += 1
    
    f.flush()
    f.close()
    
    print("Total number of wines sold is: " + str(i))


def start(filename):
    pr = cProfile.Profile()
    pr.enable()
    #read files
    df = readFiles(filename)

    #build graph
    g, source, sink, eprop_weights, friendWineEdges, friendIntNameMap, wineIntNameMap = buildGraph(df)

    #compute max flow
    residuals = push_relabel_max_flow(g, source, sink, eprop_weights)

    #write output
    writeOutput(g, residuals, friendWineEdges, friendIntNameMap, wineIntNameMap)
    
    pr.disable()

    f = open('wineStats.txt', 'w')
    s = StringIO.StringIO()
    sortby = 'cumulative'
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    ps.print_stats()
    f.write(s.getvalue())

if __name__ == "__main__":
    def usage():
        print "BloomReach Coding Challenge 1"
        print "-f FILE | --file=FILE The input file"

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                               "f:", ["file="])
    except:
        usage()
        exit()

    filename = None

    for o,a in opts:
        if o in ("-f", "--file="):
            filename = a

    try:
        start(filename)
    except (KeyboardInterrupt, SystemExit):
        exit()

