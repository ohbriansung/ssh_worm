import netifaces
import nmap


# Username and password to try
CREDENTIALS = (
    ('root', 'toor'),
    ('root', '0000'),
    ('user', 'password'),
    ('user', '12345678'),
    ('brian', '2444666668888888'),
)


def get_my_ip():
    network_interfaces = netifaces.interfaces()
    ip_addr = None

    for netFace in network_interfaces:
            try:
                addr = netifaces.ifaddresses(netFace)[2][0]['addr']
            except:  # Some KeyError exceptions here
                continue

            if addr != '127.0.0.1':
                    ip_addr = addr
                    break

    return ip_addr


def get_hosts():
    port_scanner = nmap.PortScanner()
    port_scanner.scan('192.168.2.1/24', arguments='-p -22 --open')  # Explore only sharing network
    host_info = port_scanner.all_hosts()
    live_hosts = []
    my_ip = get_my_ip()
    for host in host_info:
        if port_scanner[host].state() == 'up' and host != my_ip:
            live_hosts.append(host)

    return live_hosts


print(get_hosts())
