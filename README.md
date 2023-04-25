# prismasdwan_policy_config
Scripts for Prisma SD-WAN policy management

#### Requirements
* Active Prisma SD-WAN Account
* Python >=3.6
* Python modules:
    * CloudGenix Python SDK >= 6.1.2b1 - <https://github.com/CloudGenix/sdk-python>

#### License
MIT

#### Installation:
 - **Github:** Download files to a local directory, manually run the scripts

### Usage:
Pull resource configuration into YAML file:
```
./pull_resource.py
```
Push resource updates to the Prisma SD-WAN Controller
``` 
./push_resources.py -F <yaml file name> 
```
Pull Policy configuration into YAML:
```angular2
./pull_policy.py -PT <policy_type> 
```
Push Policy configuration to Prisma SD-WAN Controlelr:
```angular2
./push_policy.py -PT <policy_type> -F <yaml config file>
```


#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release |
