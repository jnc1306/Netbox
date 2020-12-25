import nmap
import pynetbox

# Global Variables
networks = ['192.168.50.0/24','192.168.25.0/24']


# Netbox API Connection
nb = pynetbox.api(
   'https://192.168.50.143/',
    token='9ada7fee04cdc2f59d72d9c120da77d579becd5f')


# Disable SSL Cert verification (Needs to be enabled in Production ENV)
nb.http_session.verify = False

# Initialize nmap
nm = nmap.PortScanner()

# Scan network with NMAP
nm.scan('192.168.50.0/24',arguments='-sn')

# Get state of individual ip address
status = nm['192.168.50.1'].state()

def net_scan ():
    for net in networks:
        nm.scan(net,arguments='-sn')

def ip_role (ip):
    get_ip_addr = nb.ipam.ip_addresses.get(address='{}/24'.format(ip))
    hostname = nm[ip].hostname()
    get_ip_addr.update({'address': '{}/24'.format(ip),
                         'role': 'anycast'})
def add_ip(ip):
    get_ip_addr = nb.ipam.ip_addresses.get(address='{}/24'.format(ip))
    hostname = nm[ip].hostname()
    if not get_ip_addr:
        nb.ipam.ip_addresses.create(address='{}/24'.format(ip),
                                    dns_name=hostname,
                                    description=hostname)
    else:
        get_ip_addr.update({'address': '{}/24'.format(ip),
                            'dns_name': hostname,
                            'description': hostname})

def add_device ():
    

for ip in nm.all_hosts():
    add_ip(ip)
    ip_role(ip)

#print(status, hostname, ip_addr)
