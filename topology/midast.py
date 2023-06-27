import networkx as nx
import yaml

from networkx.drawing.nx_agraph import to_agraph
from utils.log import log

class Topology():
    def __init__(self):
        self.G = nx.MultiGraph()

    def build(self):
        '''
            Summary:
            Builds a network topology from the topology.yaml file into memory, stored in a networkx Graph object.
            Once the networkx Graph object has been built, it's drawn and saved as topology.png.

            Nodes: network devices
            Node attributes: dict of attributes assigned to a specific node
            Edges: links between network devices
            Edge attributes: dict of attributes assigned to a specific edge
        '''
        log('Building topology...', 'info')

        topology_data = yaml.load(open('topology/topology.yaml'), Loader=yaml.SafeLoader)

        for topology_name, topology_vars in topology_data.items():
            log(f'Topology name: {topology_name}', 'info')

            for node, node_attributes in topology_vars['nodes'].items():
                self.G.add_node(node)
                self.G.nodes[node]['shape'] = 'box'
                for attribute_name, attribute_value in node_attributes.items():
                    self.G.nodes[node][attribute_name] = attribute_value

            for edge_number, edge_attributes in topology_vars['edges'].items():
                self.G.add_edge(edge_attributes['a_end'], edge_attributes['b_end'])
                nx.set_edge_attributes(
                    self.G, 
                    {
                        (edge_attributes['a_end'], 
                        edge_attributes['b_end'], 
                        edge_attributes['edge_index']): edge_attributes
                    }
                )

        for node1, node2, edge_attributes in self.G.edges(data=True):
            edge_attributes['label'] = f"""
            {edge_attributes['a_end']} ({self.G.nodes[edge_attributes['a_end']]['os']})
            {edge_attributes['a_end_ip']}, {edge_attributes['a_end_interface']}\n
            {edge_attributes['b_end']} ({self.G.nodes[edge_attributes['b_end']]['os']})
            {edge_attributes['b_end_ip']}, {edge_attributes['b_end_interface']}
            """

        log('Drawing topology...', 'info')
        vis = to_agraph(self.G)
        vis.layout('dot')
        vis_path = 'topology/topology.png'
        vis.draw(vis_path)
            
        log(f'Topology drawn, saved as: {vis_path}', 'info')
        log('Topology build complete', 'info')

    def get_client_calling_for_ip(self, giaddr, _type):
        '''
            Summary:
            Gets the hostname and operating system of the client calling for an IP from the networkx Graph object.

            Takes:
            giaddr: Gateway or relay IP that the DHCP packet was received from
            _type: Type of DHCP packet, if type is offer log the client name and OS

            Returns:
            client_device_name: hostname of the client device
            client_device_os: operating system of the client device
        '''
        for node1, node2, edge_attributes in self.G.edges(data=True):
            if giaddr in edge_attributes.values():
                if giaddr == edge_attributes['a_end_ip']:
                    client_device_name, client_device_os = edge_attributes['b_end'], self.G.nodes[edge_attributes['b_end']]['os']
                elif giaddr == edge_attributes['b_end_ip']:
                    client_device_name, client_device_os = edge_attributes['a_end'], self.G.nodes[edge_attributes['a_end']]['os']

                if _type == 'offer':
                    log(f'Saw client: {client_device_name}', 'info')
                    log(f'OS: {client_device_os}', 'info')

                return client_device_name, client_device_os
