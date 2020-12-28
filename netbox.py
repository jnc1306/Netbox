import nmap
import pynetbox

# Global Variables
networks = ['192.168.50.0/24','192.168.25.0/24']
dev_roles = ['Unassigned','Server','Router','Switch','Access Point']
sites = ['Unassigned','DC1','DC2']

# Netbox API Connection
nb = pynetbox.api(
   'https://192.168.50.143/',
    token='9ada7fee04cdc2f59d72d9c120da77d579becd5f')


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
                               device_role='Unassigned',
                               site='Unassigned')

def add_device_role():
    for role in dev_roles:
        get_role = nb.dcim.device_roles.get(name=role)
        if not get_role:
           nb.dcim.device_roles.create(name=role,
                                       slug=str(role).lower().replace(' ','_'),
                                       role='Unassigned')

def add_site():
    print('')



if __name__ == '__main__':
    for host in nm.all_hosts():
        hostname = nm[host].hostname()
        #add_device(hostname)
        add_ip(host)

#print(status, hostname, ip_addr)
