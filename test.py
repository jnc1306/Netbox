import nmap
import pynetbox

# Netbox API Connection
nb = pynetbox.api(
   'https://192.168.50.143/',
    token='9ada7fee04cdc2f59d72d9c120da77d579becd5f')


# Disable SSL Cert verification (Needs to be enabled in Production ENV)
nb.http_session.verify = False

nm = nmap.PortScanner()
nm.scan('192.168.50.1',arguments='-sn')
status = nm['192.168.50.1'].state()
hostname = nm['192.168.50.1'].hostname()



print(status, hostname)