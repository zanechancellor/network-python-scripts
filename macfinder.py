import netmiko
import re
from getpass import getpass

def findMac(mac, ip, username, password, secret=None):
    # Declare variables
    path=[]
        # {'name': 'Sw1', 'ip': '1.1.1.1', 'ports': [{'name': 'Gi0/1', 'vlan': '2'}]}
        
    possible_devices=[]
    
    if secret is None or secret=='':
        secret = password
    
    current_device={"ip":ip, "username":username, "password":password, "secret":secret, "device_type":"cisco_ios"}
    
    # Convert mac address to cisco format
    mac = mac.replace(":", "")
    mac = mac.replace("-", "")
    mac = mac.replace(".", "")
    mac = mac.lower()
    mac = mac[0:4] + "." + mac[4:8] + "." + mac[8:12]
    print(mac)
    
    # Loop for finding mac address
    while True:
        # Prevent loops
        if path==[]:
            result=grab_info(current_device)
        elif possible_devices==[] and path!=[]:
            return {'loop':False, 'path':path, 'error':False}
            break
        elif possible_devices!=[] and path!=[]:
            ip_list=[]
            for x in path:
                ip_list.append(x['ip'])
                
            for ip in possible_devices[0]['ip']:
                if ip  in ip_list:
                    return {'loop':True, 'path':path, 'error':'Loop detected'}
                else:
                    current_device['ip']=possible_devices[0]['ip'][0]
                    possible_devices=possible_devices[1:]
                    result=grab_info(current_device)
                    if result['error'] is None:
                        break
                    continue
        
        # Define variables
        ports=[]
        
        # Check for errors
        if result['error'] is not None:
            print(result['error'])
            return {'error':result['error'], 'path':path, 'loop':False}
        
        # Check for mac address
        for entry in result['mac_table']:
            if entry['mac']==mac:
                ports.append(entry)
                
        # Check for cdp neighbors on ports
        for neighbor in result['cdp_neighbors']:
            for x in ports:
                if x['interface']==neighbor['interface']:
                    possible_devices.append(neighbor)
                    
        path.append({"name":result['hostname'], "ip":current_device['ip'], "ports":ports})
    
    return {"loop": False, "path":path, "error":None}

def grab_info(device):
    # Declare variables
    result={'error':None, 'cdp_neighbors':[], 'mac_table':[], 'hostname':''}
    mac_regex=re.compile(r'^\s{0,3}(\d{1,4})\s+(\S+)\s+\S+\s+(\S+)$', re.MULTILINE)
    cdp_regex=re.compile(r'Device ID:\s+(\S+)[\s\S]+Interface:\s+(\S+)[\s\S]+Management address\S+((?:\s+IP address:\s\S+)+)')
    
    try:
        ssh=netmiko.ConnectHandler(**device)
        result['hostname']=ssh.find_prompt()[0:-1]
        if ssh.check_enable_mode() is False:
            ssh.enable()
    except Exception as e:
        result['error']=str(e)
        return result
    
    __unparsed_mac=ssh.send_command("show mac address-table")
    __regex_mac=re.findall(mac_regex, __unparsed_mac)
    for port in __regex_mac:
        real_port=port[2].replace("Gi", "GigabitEthernet")
        result['mac_table'].append({'vlan':port[0], 'mac':port[1], 'interface':real_port})
        
    __unparsed_cdp=ssh.send_command("show cdp neighbors detail")
    for cdp in __unparsed_cdp.split('-------------------------')[1:]:
        __regex_cdp=re.findall(cdp_regex, cdp)
        if __regex_cdp==[]:
            continue
        ips=[]
        for x in __regex_cdp[0][2].split('\n'):
            if x.strip()=='':
                continue
            ips.append(x.strip("  IP address: "))
        result['cdp_neighbors'].append({'name':__regex_cdp[0][0], 'ip':ips, 'interface':__regex_cdp[0][1].strip(",")})
        
    ssh.disconnect()
    
    return result

if __name__ == "__main__":
    # 5254.0000.001d
    result=findMac(input("Mac Address: "), input("Ip address: "), input("Username: "), getpass("Password: "), getpass("Secret (Just hit enter to use password): "))
    if result['loop'] is True:
        print("Loop detected")
    elif result['error'] is not None:
        print(result['error'])
    else:
        print(result)