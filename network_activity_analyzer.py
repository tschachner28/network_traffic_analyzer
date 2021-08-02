import os
import subprocess
import re
#os.system("sudo -S tcpdump -c 80 -n -v")
"""
output = subprocess.check_output(['sudo', '-S', 'tcpdump', '-c', '80', '-n', '-v'])
decoded_output = output.decode()
uniq_ips = []
while decoded_output.find("\n") != -1:
    source_ip_start_ind = decoded_output.find("\n") + 3
    source_ip_end_ind = decoded_output[source_ip_start_ind:].find('>') - 1
    source_ip = decoded_output[source_ip_start_ind:source_ip_start_ind+source_ip_end_ind]
    if 
    dest_ip_start_ind = decoded_output[source_ip_start_ind:].find('>') + 2
    dest_ip_end_ind = decoded_output[source_ip_start_ind:].find(':')
    dest_ip = decoded_output[source_ip_start_ind+dest_ip_start_ind:source_ip_start_ind+dest_ip_end_ind]
"""

#uniq_ips_cmd_output = subprocess.check_output(['sudo', '-S', 'tcpdump', '-n', '-v', '-c', '80', '|', 'awk', '\'{print $1}\'', '|', 'grep', '-v', ':'])
"""
tcpdump_output = subprocess.check_output(["sudo", "-S", "tcpdump", "-n", "-v", "-c", "80"])
tcpdump_output_filename = 'tcpdump_output.txt'
tcpdump_output_file = open(tcpdump_output_filename, 'w')
tcpdump_output_file.write(tcpdump_output.decode())
"""

#first_line_elements = subprocess.check_output(["awk", "{print $1}", tcpdump_output_filename]).decode()
#first_line_elements_filename = 'first_line_elements.txt'
#first_line_elements_file = open(first_line_elements_filename, "w")
#first_line_elements_file.write(first_line_elements)
#for ip_or_timestamp in first_line_elements:
#    if ip_or_timestamp.find(':') != -1:
#        continue

#established_connections = subprocess.check_output(['netstat', '-an', '|', 'grep "ESTABLISHED"', '|', 'wc', '-l']).decode().split('\n')
#num_connections_by_ip = subprocess.check_output(['netstat', '-n', '|', 'grep \'tcp\|udp\'', '|', 'awk', '{print $5}', '|', 'cut', '-d:', '-f1', '|', 'sort', '|', 'uniq', '-c', '|', 'sort', '-n']).decode()



# Input: output of whois command (string); attribute, e.g. 'country' (string)
# Output: The attribute for that IP, e.g. 'US' (string)
def find_ip_attr(whois_output, attr):
    re_ip_attr = re.search(attr, whois_output, re.IGNORECASE)
    if re_ip_attr == None:
        return None
    ip_attr_start_ind = re_ip_attr.span()[1]
    while whois_output[ip_attr_start_ind] == ' ':
        ip_attr_start_ind += 1
    ip_attr_end_ind = ip_attr_start_ind + whois_output[ip_attr_start_ind:].find('\n')
    result = whois_output[ip_attr_start_ind:ip_attr_end_ind]
    return result

output_filename = 'network_activity_analyzer_output.txt'
output_file = open(output_filename, "w")

netstat_output = subprocess.check_output(["netstat", "-n"]).decode()
netstat_output_filename = 'netstat_output.txt'
netstat_output_file = open(netstat_output_filename, "w")
netstat_output_file.write(netstat_output)
foreign_ips = subprocess.check_output(["awk", "{print $5}", netstat_output_filename]).decode().split('\n')
local_ports = subprocess.check_output(["awk", "{print $4}", netstat_output_filename]).decode().split('\n') # ports these IP addresses are accessing
potential_sus_conns = False

# Look up foreign IP addresses
for i, ip_and_port in enumerate(foreign_ips):
    if ip_and_port.count('.') < 4 or ip_and_port[0:10] == "127.0.0.1.": # not a foreign IP address
        continue
    ip_addr = ip_and_port[0:ip_and_port.rfind('.')]
    foreign_port = ip_and_port[ip_and_port.rfind('.')+1:]
    local_port = local_ports[i][local_ports[i].rfind('.')+1:]

    whois_output = subprocess.check_output(["whois", ip_addr]).decode()
    ip_country = find_ip_attr(whois_output, 'country:')
    ip_physical_address = find_ip_attr(whois_output, 'address:')
    ip_owner = find_ip_attr(whois_output, 'owner:')
    ip_email = find_ip_attr(whois_output, 'e-mail:')
    ip_person = find_ip_attr(whois_output, 'person:')

    if ip_country != 'US' or local_port in ['21,', '22', '23', '25', '3306', '3309']:
        if not potential_sus_conns:
            output_file.write('Potentially suspicious connections:\n')
            potential_sus_conns = True
        output_file.write('IP address: ' + ip_addr + '\n')
        output_file.write('Country: ' + ip_country + '\n')
        output_file.write('Address: ' + ip_physical_address + '\n' if ip_physical_address is not None else '')
        output_file.write('Owner: ' + ip_owner + '\n' if ip_owner is not None else '')
        output_file.write('Email: ' + ip_email + '\n' if ip_email is not None else '')
        output_file.write('Person: ' + ip_person + '\n' if ip_person is not None else '')

    # Check local ports being accessed
    if local_port == '21':
        output_file.write('This IP address is accessing port 21, which is used for FTP' + '\n')
    elif local_port == '22':
        output_file.write('This IP address is accessing port 22, which is used for SSH' + '\n')
    elif local_port == '23':
        output_file.write('This IP address is accessing port 23, which is used for telnet' + '\n')
    elif local_port == '25':
        output_file.write('This IP address is accessing port 25, which is used for SMTP' + '\n')
    elif local_port == '3306':
        output_file.write('This IP address is accessing port 3306, which is used for MySQL' + '\n')
    elif local_port == '3389':
        output_file.write('This IP address is accessing port 3389, which is used for RDP' + '\n')

    if ip_country != 'US' or local_port in ['21,', '22', '23', '25', '3306', '3309']:
        output_file.write('\n')



# Detect possible DDoS attacks
# Detect possible SYN flood by comparing number of SYN_RECV connections to number of ESTABLISHED connections
netstat_output_connections = netstat_output.split('\n')
established_connections = 0
syn_recv_connections = 0
for connection in netstat_output_connections:
    if connection.find('ESTABLISHED') != -1:
        established_connections += 1
    elif connection.find('SYN_RECV') != -1:
        syn_recv_connections += 1
if syn_recv_connections > established_connections:
    output_file.write("Possible SYN flood attack:\n")
    output_file.write(str(syn_recv_connections) + ' SYN_RECV connections ' and str(established_connections) + ' ESTABLISHED connections\n')
    output_file.write('\n')
# Check for unusually large number of connections by any IP
command = 'netstat -n |grep \'tcp\|udp\' | awk \'{print $5}\' | cut -d: -f1 | sort | uniq -c | sort -n'
p = subprocess.Popen(
    command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
ips_num_connections_list = []
ips_num_connections_dict = {}
for line in iter(p.stdout.readline, b''):
    ips_num_connections_list.append(line.decode().replace('\n',''))
    start_ind = 0
    line = line.decode()
    if line.count('.') < 4:
        continue # not a valid IP address
    while line[start_ind] == ' ':
        start_ind += 1
    num_connections = int(line[start_ind:start_ind+line[start_ind:].find(' ')])
    start_ind += 1
    while line[start_ind] == ' ':
        start_ind += 1
    end_ind = line.rfind('.')
    ip = line[start_ind:end_ind]
    ips_num_connections_dict[ip] = num_connections
sorted_ips_num_connections = sorted(ips_num_connections_dict.items(), key=lambda x: x[1])
output_file.write("IP addresses with the most connections: \n")
curr_ind = len(sorted_ips_num_connections)-1
while curr_ind >= len(sorted_ips_num_connections)-6:
    ip_num_connections_line = sorted_ips_num_connections[curr_ind][0] + ": " + str(sorted_ips_num_connections[curr_ind][1]) + "\n"
    output_file.write(ip_num_connections_line)
    curr_ind -= 1
output_file.write("A suspiciously large number of connections by any of these IP addresses could indicate a DDoS attack.\n")

# Check for null attack

# Suspicious if:
# first syn contains payload
