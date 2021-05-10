import nmap
import pynetbox
from pprint import pprint

# Global Variables
networks = ['192.168.50.0/24']
dev_roles = ['Unassigned','Server','Router','Switch','Access Point']
dev_types = ['R210','UCS','30E','Unknown']
manufacturers = ['Cisco','Dell','Ubiquiti','Fortigate','Unknown']
sites = ['Unassigned','DC1','DC2']

# Netbox API Connection
nb = pynetbox.api(
        'http://192.168.50.75:8000/',
    token='3fe7ab39b2a1a5476214c0928e278e6d1905c94a')

# Disable SSL Cert verification (Needs to be enabled in Production ENV)
nb.http_session.verify = False

# Initialize nmap
nm = nmap.PortScanner()

# Scan network with NMAP
nm.scan('192.168.50.0/24',arguments='-sP')

def net_scan ():
    for net in networks:
        nm.scan(net,arguments='-sn')

def ip_role (host):
    get_ip_addr = nb.ipam.ip_addresses.get(address='{}/24'.format(ip))
    hostname = nm[ip].hostname()
    get_ip_addr.update({'address': '{}/24'.format(ip),
                         'role': 'anycast'})
def add_ip(host):
    get_ip_addr = nb.ipam.ip_addresses.get(address='{}/24'.format(host))
    hostname = nm[host].hostname()
    if not get_ip_addr:
        nb.ipam.ip_addresses.create(address='{}/24'.format(host),
                                    dns_name=hostname,
                                    description=hostname)
    else:
        get_ip_addr.update({'address': '{}/24'.format(host),
                            'dns_name': hostname,
                            'description': hostname})

def add_device (hostname):
    get_device = nb.dcim.devices.get(name=hostname)
    if not get_device:
        nb.dcim.devices.create(name=hostname,
                               device_role=12,device_type=7,
                               manufacturer=14,site=2)

def add_device_role():
    for role in dev_roles:
        get_role = nb.dcim.device_roles.get(name=role)
        if not get_role:
           nb.dcim.device_roles.create(name=role,
                                       slug=str(role).lower().replace(' ','_'),
                                       role='Unassigned')

def add_device_type():
    for type in dev_types:
        get_type = nb.dcim.device_types.get(model=type)
        if not get_type:
           nb.dcim.device_types.create(model=type,manufacturer=14,
                                       slug=str(type).lower().replace(' ','_'))
def add_brand():
    for brand in manufacturers:
        get_brand = nb.dcim.manufacturers.get(name=brand)
        if not get_brand:
           nb.dcim.manufacturers.create(name=brand,
                                       slug=str(brand).lower().replace(' ','_'))

def get_info():
  #test = nb.dcim.manufacturers.choices()
  #for i in test:
  pprint(nb.dcim.device_types.choices())




def add_site():
    for site in sites:
        get_site = nb.dcim.sites.get(name=site)
        if not get_site:
            nb.dcim.sites.create(name=site,slug=str(site).lower().replace(' ','_'))


if __name__ == '__main__':
    #nm.scan('192.168.50.0/24',arguments='-sP')
    for host in nm.all_hosts():
        hostname = nm[host].hostname()
        print(hostname)

    #add_site()
    #add_brand()
    #add_device_role()
    #add_device_type()

    #for host in nm.all_hosts():
    #    hostname = nm[host].hostname()
    #    print(hostname)
    #    #add_device(hostname)
    #    add_ip(host)


    #get_info()

#print(status, hostname, ip_addr)
