import yaml

from jinja2 import Environment, FileSystemLoader
from utils.log import log

class Provisioning():
    def render(self, topology):
        '''
            Summary:
            Builds a configuration file for all network devices in the topology.

            Takes: 
            topology: networkx Graph object detailing the network topology
        '''
        log('Rendering configs...', 'info')
        for node in topology.G.nodes:
            if topology.G.nodes[node].get('no_render') == True:
                continue

            node_os = topology.G.nodes[node]['os']

            template_path = Environment(loader=FileSystemLoader('provisioning/templates/'), trim_blocks=True, lstrip_blocks=True)
            device_vars = yaml.load(open('provisioning/vars/' + node + '.yaml'), Loader=yaml.SafeLoader)

            template = template_path.get_template(node_os + '.j2')
            rendered_config = template.render(device_vars)

            config_path = '/srv/tftp/configs/' + node + '.conf'

            with open(config_path, 'w') as configuration:
                configuration.write(rendered_config)

            log(f'Rendered {config_path}', 'info')

        log('Config rendering complete', 'info')
