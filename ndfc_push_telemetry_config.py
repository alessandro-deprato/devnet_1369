
import variables
from libs import ndi,nxapi
ndc = ndi.Ndi("10.58.30.1", api_key=variables.ndi_ndfc_api_key, insight_group="DC-MIL")
sites = [site["name"] for site in (ndc.get_site_groups("DC-MIL")[0]["assuranceEntities"])]
nodes = {site:[node for node in ndc.get_nodes_by_site(site)] for site in sites}
for site in nodes:
    for node in nodes[site]:
        print(f"# {site}: {node['nodeName']} -- {node['serial']} -- {node['nodeMgmtpIp']}")
        commands = " ;".join(ndc.get_node_sw_telemetry_config(site,node["serial"]).splitlines())
        cnx = nxapi.Nexus_api(node['nodeMgmtpIp'],{"username":"admin","password":"Cisco123!"})
        if not cnx.push_config(commands):
            print(f"I could NOT push the configs on {node['nodeName']}")
        else:
            print(f"Changes applied on {node['nodeName']}")