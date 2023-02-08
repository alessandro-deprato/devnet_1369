import re
import sys
import json
import pynetbox
import variables
import libs.ndi as ndi
import libs.apic as apic
import libs.utils as utils
from time import sleep
from jinja2 import Template

# Defining global vars
# Using them just for the sake of simplicity in this demo wrapper
ndc = ndi.Ndi("")
ipam_data = dict()
rendered_data = dict()
notifications = list()
apic_conn = apic.Apic("")
configuration = str()
pcv_result = dict()


# Logging
LOG = utils.log_manager(True, variables.log_file, "devnet")


def connect_to_ndi():
    """
    Creates a globally available Nexus Dashboard Connection
    :return: None
    """

    global ndc
    ndc = ndi.Ndi(variables.nd_host, api_key=variables.nd_api_key, insight_group=variables.insight_group)
    return ndc


def acquire_ipam_data():
    """
    Creates dict that follow this structure
    :return: None
    {
    "mytenant1":["100.64.0.254/24","100.64.1.254/24"],
    "mytenant2":["100.64.4.254/24","100.64.5.254/24"],
    "mytenant3":["100.64.4.254/24","100.64.6.254/24"],
    }
    Subnet overlaps in different tenants are allowed. Overlaps in same tenant over multiple VRFs are possible but
    not part of this example.
    Subnets MUST match ACI Bridge Domain IP
    """
    LOG.info("Establishing connection to IPAM")
    my_ipam = pynetbox.api(
        'http://10.50.128.147:8000',
        variables.ipam_token
    )
    # List of tenants that we will pull from the IPAM, it matching ACI tenants

    ipam_tenants = ["cleur_23_production_tn",
                    "cleur_23_development_tn",
                    "cleur_23_shared_tn"]
    global ipam_data
    ipam_data = {tenant: [] for tenant in ipam_tenants}
    for prefix in list(my_ipam.ipam.prefixes.filter(tenant=ipam_tenants)):
        if prefix.custom_fields["gateway"]:
            ipam_data[prefix.tenant.name].append(prefix.custom_fields["gateway"])
    LOG.info(f"Collected {len(ipam_data)} Tenants from IPAM")
    return None


def build_compliance_requirements():
    """
    Creates a dictionary containing the requirement name and content. Information is pulled from ipam_data
    {"requirement_name":rendered_template}
    :return: None
    """
    global rendered_data
    for tenant, subnets in ipam_data.items():
        j2_template = Template(open("templates/subnet_compliance.json.j2").read())
        rendered = j2_template.render({"tenant_name": tenant,
                                       "subnets": subnets})

        rendered_data[f"{tenant}_ipam_requirements"] = rendered
        with open(f"generated_files/{tenant}_requirements.template", "w") as file:
            LOG.debug(f"Writing file {tenant}_requirements.template")
            file.write(rendered)

    LOG.info(f"Rendered {len(rendered_data)} tenants")
    return None


def push_compliance_requirements():
    """
    Tries to upload the requirements in NDI, if the requirement is there AND if it is different from the generated one
    then it will replace it.
    :return: None
    """
    existing_templates_names = {item["name"]: item["uuid"] for item in ndc.get_all_template_compliance_rules()}
    for template_name, rendered_template in rendered_data.items():
        if template_name in existing_templates_names:
            LOG.info(f"{template_name} already on NDI, checking contents")
            if not (json.loads(rendered_template) == ndc.get_compliance_template_file(
                    f"{template_name}")):
                LOG.info(f"NDI {template_name} not matching")
                LOG.info(f"NDI {template_name} will be uploaded")
                ndc.delete_compliance_template_rule(f"{existing_templates_names[template_name]}")
                LOG.info(f"NDI {template_name} deleted")
                sleep(10)
                ndc.create_compliance_template_rule(f"{template_name}",
                                                    "Automatically maintained list", rendered_template, [variables.site_name])
                LOG.info(f"NDI {template_name} created")
            else:
                LOG.info(f"NDI {template_name} same as rendered. No action")
        else:
            LOG.info(f"{template_name} not on NDI, will push it now")
            ndc.create_compliance_template_rule(f"{template_name}",
                                                "Automatically maintained list", rendered_template, [variables.site_name])
    LOG.info("Stopping Active Assurance Jobs")
    ndc.stop_assurance_analysis(variables.site_name)
    sleep(30)
    LOG.info(f"Starting a new Assurance Job for {variables.site_name}")
    ndc.start_assurance_analysis(variables.site_name)
    return None


def read_compliance_alerts():
    """
    The Goal here is to read via the NDI API the active alerts and filter the ones related to the
    IPAM compliance.
    :return:  None
    """
    existing_templates_names = {item["name"]: item["uuid"] for item in ndc.get_all_template_compliance_rules()}
    compliance_alerts = ndc.get_anomalies(f"&fabricName={variables.site_name}&filter=category:Compliance AND severity:critical \
    AND acknowledged:false AND cleared:false&insightsGroupName={variables.insight_group}&")
    # At this point we will get all anomalies for configuration compliance, but we want only the ones affecting
    # our IPAM requirements so we need to dig one more level
    global notifications
    for alert in compliance_alerts:
        alert_details = ndc.get_anomaly_affected_objects(alert["anomalyId"], variables.site_name)
        compliance_name, tenant_name, bridge_domain, missing_ip = None, None, None, None
        for compliance_object in alert_details["value"]["data"][0]["primaryAffectedObject"]["compositeKey"]:
            if compliance_object["type"] == "NI_OBJECT_TYPE_COMPLIANCE_REQUIREMENT":
                compliance_name = compliance_object["name"]
                tenant_name = compliance_object["name"].replace('_ipam_requirements', '')
            if compliance_object["type"] == "NI_OBJECT_TYPE_GOLDEN_CONFIGURATION_OBJECT":
                missing_ip = re.findall("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}", compliance_object["name"])
                bridge_domain = compliance_object["identifier"].split("/BD-")[1].split("/")[0]
        if compliance_name and compliance_name in existing_templates_names.keys():
            notifications.append({"tenant": tenant_name,
                                  "bd": bridge_domain,
                                  "ip": ','.join(missing_ip),
                                  "anomaly_id": alert["anomalyId"],
                                  "insight_group": variables.insight_group,
                                  "site_name": variables.site_name})
            LOG.warning(f"Anomaly on {tenant_name}, IP"
                        f" {','.join(missing_ip)} is assigned to {bridge_domain}")

    return None


def apic_connect():
    """
     Creates a globally available APIC Connection
    :return: None
    """

    global apic_conn
    apic_conn = apic.Apic(variables.apic_host)
    apic_conn.get_apic_token(variables.apic_credentials)
    return None


def generate_configs():
    """
    :return:
    """
    objects = [("cleur_23_production_tn", "fvBD", "frontend_bd"),
               ("cleur_23_production_tn", "fvAEPg", "frontend_epg")]

    global configuration
    configuration = {
        "fvTenant": {"attributes": {"name": "cleur_23_development_tn", "dn": "uni/tn-cleur_23_development_tn"
                } , "children": [{"fvAp": {"attributes": {"name": "marvel_app"}, "children": []}}]}}

    attributes_exclude = ["dn"]
    for obj in objects:
        original_object = apic_conn.get_aci_object(f"/mo/uni/tn-{obj[0]}.json", query_target="subtree",
        rsp_subtree="full", rsp_prop_include="config-only", query_target_filter=f'eq({obj[1]}.name,"{obj[2]}")',
        target_subtree_class=f"{obj[1]}")["imdata"][0]
        new_obj = {obj[1]: {"attributes": {"name": "%s" % (obj[2])}, "children": []}}
        for attribute in original_object[obj[1]]["attributes"].keys():
            if attribute not in attributes_exclude:
                new_obj[obj[1]]["attributes"].update(
                    {attribute: original_object[obj[1]]["attributes"][attribute]})
        new_obj[obj[1]]["children"] = original_object[obj[1]]["children"]
        if obj[1] == "fvBD":
            configuration["fvTenant"]["children"].append(new_obj)
        elif obj[1] == "fvAEPg":
            for child in configuration["fvTenant"]["children"]:
                if "fvAp" in child.keys():
                    child["fvAp"]["children"].append(new_obj)

    with open(f"generated_files/apic_config.json", "w") as file:
        LOG.info(f"Writing file apic_config.json")
        file.write(json.dumps(configuration))
    return None


def generate_configs_v2():
    """
    :return:
    """
    objects = [("cleur_23_production_tn", "fvBD", "frontend_bd"),
               ("cleur_23_production_tn", "fvAEPg", "frontend_epg")]

    global configuration
    configuration = {
        "fvTenant": {"attributes": {"name": "cleur_23_development_tn", "dn": "uni/tn-cleur_23_development_tn"
                } , "children": [{"fvAp": {"attributes": {"name": "marvel_app"}, "children": []}}]}}

    attributes_exclude = ["dn"]
    for obj in objects:
        original_object = apic_conn.get_aci_object(f"/mo/uni/tn-{obj[0]}.json", query_target="subtree",
        rsp_subtree="full", rsp_prop_include="config-only", query_target_filter=f'eq({obj[1]}.name,"{obj[2]}")',
        target_subtree_class=f"{obj[1]}")["imdata"][0]
        new_obj = {obj[1]: {"attributes": {"name": "%s" % (obj[2])}, "children": []}}
        for attribute in original_object[obj[1]]["attributes"].keys():
            if attribute not in attributes_exclude:
                new_obj[obj[1]]["attributes"].update(
                    {attribute: original_object[obj[1]]["attributes"][attribute]})
        for c_item in original_object[obj[1]]["children"]:
            if "fvSubnet" in c_item.keys():
                c_item["fvSubnet"]["attributes"]["scope"] = \
                    c_item["fvSubnet"]["attributes"]["scope"].replace(",shared","")
                new_obj[obj[1]]["children"].append(c_item)
            elif "fvRsCons" in c_item.keys() and \
                    c_item["fvRsCons"]["attributes"]["tnVzBrCPName"] == "cleur23_user_any_con":
                pass
            else:
                new_obj[obj[1]]["children"].append(c_item)
        if obj[1] == "fvBD":
            configuration["fvTenant"]["children"].append(new_obj)
        elif obj[1] == "fvAEPg":
            for child in configuration["fvTenant"]["children"]:
                if "fvAp" in child.keys():
                    child["fvAp"]["children"].append(new_obj)

    with open(f"generated_files/apic_config.json", "w") as file:
        LOG.info(f"Writing file apic_config.json")
        file.write(json.dumps(configuration))
    return None

def push_to_apic():
    """
    :return: None
    """
    LOG.info("Triggering a snapshot on APIC")
    apic_conn.take_snapshot("adp", 5)
    if apic_conn.api_post(url="mo/uni/tn-cleur_23_development_tn.json", json_body=configuration):
        LOG.info("Configuration loaded on APIC")
    else:
        LOG.error("Configuration NOT loaded on APIC")
    return None


def run_pcv():
    """
    :return: None
    """
    global pcv_result
    LOG.info("Submitting PCV Job")
    ndc.stop_assurance_analysis(variables.site_name)
    sleep(30)
    pcv_result = (ndc.new_pcv_job(variables.site_name, json.dumps(configuration)))
    if pcv_result:
        LOG.info("PCV Job Submitted correctly")
    else:
        LOG.error("Could not submit PCV Job")
    return None


def wait_pcv():
    """
    :return:
    """
    global pcv_result
    current_pcv = pcv_result['value']['data']
    while current_pcv['analysisStatus'] != "COMPLETED":
        try:
            sleep(30)
            current_pcv = ndc.get_pcv_status(current_pcv['jobId'], site_name=variables.site_name)
            LOG.info(f"PCV Status: {current_pcv['analysisStatus']}")
        except KeyboardInterrupt:
            LOG.info("\nBored about waiting, no problem!\n")
            LOG.info("PCV Analysis Wait Stopped")
            sys.exit(1)
    LOG.info("PCV Analysis Completed")
    pcv_result = ndc.get_pcv_by_id(current_pcv["jobId"],variables.site_name)
    return None


def read_delta_analysis():
    """
    :return:
    """

    delta_data = ndc.get_delta_analysis_by_id(pcv_result["value"]["data"]["assuranceEntityName"],
                                              pcv_result["value"]["data"]["epochDeltaJobId"])

    for aggregated_anomaly in delta_data["value"]["data"]:
        item_severity = re.findall(r"EVENT_SEVERITY_(.*)",aggregated_anomaly["bucket"])
        if item_severity[0] not in ["MAJOR", "CRITICAL"]:
            continue
        event_count = {x["bucket"]: x["count"] for x in aggregated_anomaly["output"]}
        LOG.info(f'PCV found {event_count["EPOCH2_ONLY"]} new {",".join(item_severity)} anomalies')
        for anomaly in ndc.get_delta_analysis_anomalies(
                variables.site_name, pcv_result["value"]["data"]["epochDeltaJobId"], "EPOCH2_ONLY",

                aggregated_anomaly["bucket"])["entries"]:
            LOG.error(f"Anomaly:{anomaly['anomalyStr']}")


def main():
    """
    This is a demo runner script to be used during CLEUR23 DEVNET-1369
    """

    args = utils.args_manager()
    LOG.info("Demo Start, Welcome Everyone")
    input("Press Enter to continue...")

    demo_list = {
        "demo_1": [
            connect_to_ndi,
            acquire_ipam_data,
            build_compliance_requirements,
            push_compliance_requirements,
            read_compliance_alerts,
            acquire_ipam_data,
            build_compliance_requirements,
            push_compliance_requirements
        ],
        "demo_2": [
            apic_connect,
            generate_configs,
            connect_to_ndi,
            run_pcv,
            wait_pcv,
            read_delta_analysis,
            generate_configs_v2,
            acquire_ipam_data,
            build_compliance_requirements,
            push_compliance_requirements,
            run_pcv,
            wait_pcv,
            read_delta_analysis,
            push_to_apic,
        ]
    }

    for current_function in demo_list[args.demo]:
        next_step = False
        LOG.info(f"Running {current_function.__name__}")
        while not next_step:
            current_function()
            next_step = not (utils.query_yes_no("\nDo you want to repeat the task?"))

    LOG.info("Demo Completed, Thank you")


if __name__ == "__main__":
    # Catch CTRL-C
    try:
        main()

    except KeyboardInterrupt as e:
        print("\nCTRL-C caught, interrupting Demo\n")
        sys.exit(1)
