# midas
A topology aware zero touch provisioning (ZTP) tool for network devices.

## Supported operating systems:
  - Juniper Junos
  - Cisco IOS

## Modules
### midasd
The socket DHCP portion of midas.

### midast
The networkx topology portion of midas.

### midasp
The YAML/Jinja provisioning portion of midas.

## Installation / usage
```
  $ cd midas
  $ chmod +x midas
  $ sudo ./midas
```

## Tips
  - When building your topology.yaml the visualisation builds top to bottom, arrange your nodes and edges in such a way that they correspond to the correct side of the graph, for neatness.

## Dependencies
  - networkx
  - pygraphviz
  - yaml
  - jinja2
