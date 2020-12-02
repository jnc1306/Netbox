# Netbox
Project to automate Netbox Inventory

# Requirements  
Requirements:
- pynetaddr (requirements.txt file)
- ansible collection: netbox.Netbox

- Install the ansible collection with ansible-galaxy collection install netbox.netbox

Currently the main.yml file can run against a host file to gather facts and add the following information.

- ip address/cidr
- Description (Currently the OS of remote system)
- DNS Hostname (ansible_hostname variable)
