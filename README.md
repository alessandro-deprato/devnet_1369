# DEVNET 1369

## Script Installation 

Install the additional required libraries
```bash
pip install -r requirements.txt 
```

## Nexus-as-Code
Install Terraform and then take a look here:

https://developer.cisco.com/docs/nexus-as-code/

**Make sure that below configurations will not alter your fabric. Some objects will be pushed under the common tenant as well**

Edit the file aci_tenant_config/main.tf and provide your ACI URL, username and password

Once everything ready you can push the TF configuration contained in aci_tenant_config

```bash
cd aci_tenant_config

terraform init

terraform plan

terraform apply
```

# Note on IPAM Connector
Make sure you import the data from your IPAM connector in a proper way

```python
{
    "mytenant1":["100.64.0.254/24","100.64.1.254/24"],
    "mytenant2":["100.64.4.254/24","100.64.5.254/24"],
    "mytenant3":["100.64.4.254/24","100.64.6.254/24"],
}
```
# Usability

The demo_runner has been built to run w/o interdependencies between the different functions. Feel free to use and play with the as you wish. This is not a production script at all. You should consider to use it as a discovery method for learning how to play with NDI API. 
