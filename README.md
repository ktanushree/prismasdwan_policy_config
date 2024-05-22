## prismasdwan_policy_config
Scripts for Prisma SD-WAN policy management.
The policy management scripts are a set of 4 scripts that can be used to manage Prisma SD-WAN policies and the resources that make up the policy rules.

Prisma SD-WAN policy rules are reference resources such as applications, prefix filters, security zones, circuit labels, service and DC groups, etc.
These resources can be entirely managed using the pull_resources.py and push_resources.py scripts.

The scripts **pull_resources.py** and **push_resources.py** can be used to:
- Take backup of existing resources viz. custom apps, prefix filters, security zones, service and DC groups, circuit labels, etc.
- Create, update and delete resources viz. custom apps, prefix filters, security zones, service and DC groups, circuit labels, etc.

Once the resources are in the desired state, the pull_policy.py and push_policy.py scripts can be used for policy management viz. stacks, sets and rules.

The scripts **pull_policy.py** and **push_policy.py** can be used to:
- Take backup of existing policy rules, sets and stacks
- Create, update and delete policy rules, sets and stacks 

## Requirements
* Active Prisma SD-WAN Account
* Python >=3.6
* Python modules:
    * CloudGenix Python SDK >= 6.2.3b1 - <https://github.com/CloudGenix/sdk-python>
    * Prisma SASE Python SDK >= 6.2.3b1 - <https://github.com/PaloAltoNetworks/prisma-sase-sdk-python>


## License
MIT

## Installation:
 - **Github:** Download files to a local directory, manually run the scripts

## Usage:
### Resource Management
Pull resource configuration into YAML file:
```
./pull_resource.py
```
Push resource updates to the Prisma SD-WAN Controller
``` 
./push_resources.py -F <yaml file name> 
```

### Path Policy Management
Pull Path Policy configuration into YAML:
```angular2
./pull_policy.py -PT path 
```
Push Path Policy configuration to Prisma SD-WAN Controlelr:
```angular2
./push_policy.py -PT path -F <yaml config file>
```

### QoS Policy Management
Pull QoS Policy configuration into YAML:
```angular2
./pull_policy.py -PT qos 
```
Push QoS Policy configuration to Prisma SD-WAN Controlelr:
```angular2
./push_policy.py -PT qos -F <yaml config file>
```

### NAT Policy Management
Pull NAT Policy configuration into YAML:
```angular2
./pull_policy.py -PT nat 
```
Push NAT Policy configuration to Prisma SD-WAN Controlelr:
```angular2
./push_policy.py -PT nat -F <yaml config file>
```

### Security Policy Management
Pull Security Policy configuration into YAML:
```angular2
./pull_policy.py -PT security 
```
Push Security Policy configuration to Prisma SD-WAN Controlelr:
```angular2
./push_policy.py -PT security -F <yaml config file>
```

### Download ALL Policies
Pull ALL Policy configuration into a single YAML file:
```angular2
./pull_policy.py -PT all --output allpolicyconfig.yml
```
Pull ALL Policy configuration into a separate YAML files:
```angular2
./pull_policy.py -PT all 
```

## Help Text:
#### pull_resources.py
```
(base) Tanushree's Macbook Pro:policy_config tkamath$ ./pull_resources.py -h
usage: pull_resources.py [-h] [--controller CONTROLLER] [--output OUTPUT]

Policy Tool: Pull Resources.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod: https://api.elcapitan.cloudgenix.com

Resource Properties:
  Information shared here will be used to query resources

  --output OUTPUT       Output file name
(base) Tanushree's Macbook Pro:policy_config tkamath$
```

#### push_resources.py
```
(base)Tanushree's Macbook Pro:policy_config tkamath$ ./push_resources.py -h
usage: push_resources.py [-h] [--controller CONTROLLER] [--filename FILENAME]

Policy Tool: Push Resources.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod: https://api.elcapitan.cloudgenix.com

Resource Properties:
  Information shared here will be used to configure resources

  --filename FILENAME, -F FILENAME
                        File name. Provide the entire path
(base)Tanushree's Macbook Pro:policy_config tkamath$ 
```

#### pull_policy.py
```
(base)Tanushree's Macbook Pro:policy_config tkamath$ ./pull_policy.py -h
usage: pull_policy.py [-h] [--controller CONTROLLER] [--policytype POLICYTYPE] [--output OUTPUT]

Policy Tool: Pull Policy.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod: https://api.elcapitan.cloudgenix.com

Policy Properties:
  Information shared here will be used to query policies

  --policytype POLICYTYPE, -PT POLICYTYPE
                        Policy Type. Allowed values: path, qos, nat, security, all
  --output OUTPUT       Output file name
(base)Tanushree's Macbook Pro:policy_config tkamath$
```

#### push_policy.py
```
(base)Tanushree's Macbook Pro:policy_config tkamath$ ./push_policy.py -h
usage: push_policy.py [-h] [--controller CONTROLLER] [--policytype POLICYTYPE] [--filename FILENAME]

Policy Tool: Push Policy.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod: https://api.elcapitan.cloudgenix.com

Policy Properties:
  Information shared here will be used to query policies

  --policytype POLICYTYPE, -PT POLICYTYPE
                        Policy Type. Allowed values: path, qos, nat, security, all
  --filename FILENAME, -F FILENAME
                        File name. Provide the entire path
(base)Tanushree's Macbook Pro:policy_config tkamath$
```

## Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b4** | Bug fix for git issue#3 |
| **1.0.0** | **b3** | Bug fixes for git issue #1 and #2. Added fix to manage customapps |
| **1.0.0** | **b2** | Added support for all policy types. Bug fixes |
| **1.0.0** | **b1** | Initial Release |
