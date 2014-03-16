import scapy.all
import pydot

#graph = pydot.Dot(graph_type='digraph', overlap="prism")
#graph = pydot.Dot(graph_type='digraph', overlap="scale")
graph = pydot.Dot(graph_type='digraph', overlap="false", bb="0,0,700,700")
graph.set_node_defaults(fontsize=8)

pkts = scapy.all.rdpcap("nitroba.pcap")
ips = set()

for pkt in pkts:
    (s,d) = pkt.sprintf("%IP.src%"), pkt.sprintf("%IP.dst%")
    if (s,d) not in ips:
        ips.add((s,d))
        # Add the edge between the two IP addresses.
        e = pydot.Edge(s,d)

        # Add the edge to the graph.
        graph.add_edge(e)


graph.write('netmap_topo.png', prog='twopi', format='png')
graph.write_raw('netmap_topo.dot')
#print ips
