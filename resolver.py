import sys
import socket
import random
from struct import *


def networkToList(fileName):
    """
    Makes a list structure holding the ip addresses from a root-servers list

    Args:
        fileName : The file to read from
    Returns: 
        networkList : A list of the root ip 
    """
    networkList = []
    file = open(fileName, 'r')
    for line in file:
        networkList.append(line.strip())
    file.close()
    return networkList


def stringToNetwork(orig_string):
    """
    Converts a standard string to a string that can be sent over
    the network.

    Args:
        orig_string (string): the string to convert

    Returns:
        bytes: The network formatted string (as bytes)

    Example:
        stringToNetwork('www.sandiego.edu.edu') will return
          (3)www(8)sandiego(3)edu(0)
    """
    ls = orig_string.split('.')
    toReturn = b""
    for item in ls:
        formatString = "B"
        formatString += str(len(item))
        formatString += "s"
        toReturn += pack(formatString, len(item), item.encode())
    toReturn += pack("B", 0)
    return toReturn


def networkToString(response, start):
    """
    Converts a network response string into a human readable string.

    Args:
        response (string): the entire network response message
        start (int): the location within the message where the network string
            starts.

    Returns:
        string: The human readable string.

    Example:  networkToString('(3)www(8)sandiego(3)edu(0)', 0) will return
              'www.sandiego.edu'
    """

    toReturn = ""
    position = start
    length = -1
    while True:
        length = unpack("!B", response[position:position+1])[0]
        if length == 0:
            position += 1
            break

        # Handle DNS pointers (!!)
        elif (length & 1 << 7) and (length & 1 << 6):
            b2 = unpack("!B", response[position+1:position+2])[0]
            offset = 0
            for i in range(6) :
                offset += (length & 1 << i)
            for i in range(8):
                offset += (b2 & 1 << i)
            dereferenced = networkToString(response, offset)[0]
            return toReturn + dereferenced, position + 2

        formatString = str(length) + "s"
        position += 1
        toReturn += unpack(formatString, response[position:position+length])[0].decode()
        toReturn += "."
        position += length
    return toReturn[:-1], position
    

def constructQuery(ID, hostname, mx):
    """
    Constructs a DNS query message for a given hostname and ID.

    Args:
        ID (int): ID # for the message
        hostname (string): What we're asking for

    Returns: 
        string: "Packed" string containing a valid DNS query message
    """
    flags = 0 # 0 implies basic iterative query

    # one question, no answers for basic query
    num_questions = 1
    num_answers = 0
    num_auth = 0
    num_other = 0

    # "!HHHHHH" means pack 6 Half integers (i.e. 16-bit values) into a single
    # string, with data placed in network order (!)
    header = pack("!HHHHHH", ID, flags, num_questions, num_answers, num_auth,
            num_other)

    qname = stringToNetwork(hostname)

    # Resolve qtype
    if mx is True:
        qtype = 15 # request MX type
    else:
        qtype = 1 # request A type

    remainder = pack("!HH", qtype, 1)
    query = header + qname + remainder
    return query

def sendToServer(server, hostname, mx):
    """
    Compresses send and receive operations into one function call

    Args:
        server: server ip
        hostname: Host Name
        flag: MX flag 

    Return:
        response: The response from server
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)   # socket should timeout after 10 seconds

    random_id = random.randint(1, 65535)
    query = constructQuery(random_id, hostname, mx)

    try:
        # send the message to 172.16.7.15 (the IP of USD's DNS server)
        #print("Query server: " + server)
        sock.sendto(query, (server, 53)) #use root-servers list
        response = sock.recv(4096)
        sock.close()
        return response

    except socket.timeout as e:
        print("Timeout", e)

def findType(data):
    """
    Function to grab the type int from received data

    Args:
        Data received from socket
    
    Return:
        Int value from type field
    """
    start = networkToString(data, 12)[1] + 4
    start = networkToString(data, start)[1]
    type = data[start : start + 2]
    type = type[len(type)-1]
    return type

def findCname(data):
    """
    Function to grab the cname from received data

    Args:
        Data received from socket
    
    Return:
        CNAME value from type 5 - CNAME
    """
    start = networkToString(data, 12)[1] + 4
    start = networkToString(data, start)[1] + 10
    cname = networkToString(data, start)[0]
    return cname

def findMail(data):
    """
    Function to grab the mail exchange from received data. 

    Args:
        Data received from socket
    
    Return:
        Mail exchange from returned MX record
    """
    start = networkToString(data, 12)[1] + 4
    start = networkToString(data, start)[1] + 12
    mail = networkToString(data, start)[0]
    return mail


def findAnswer(data, ns_count):
    """
    Function to grab the ip address from answer resource record

    Args:
        Data received from socket
    
    Return:
        IP of resolved host
    """
    start = networkToString(data, 12)[1] + 4
    start = networkToString(data, start)[1]
    ip = data[start+10 : start+14]
    return socket.inet_ntoa(ip)


def createNS(data, ns_count):
    """
    Function to create a new list of name servers returned by server

    Args:
        Data received from socket
    
    Return:
        list of NS names to check
    """
    nsList = []
    start = networkToString(data, 12)[1] + 4
    #start = networkToString(data, start)[1] + 12
    for i in range(0, ns_count):
        start = networkToString(data, start)[1]
        nsList.append(networkToString(data, start + 10)[0])
        start = networkToString(data, start + 10)[1]
        i = i+1
    
    return nsList
            


def parseResponse(response):
    """
    Unpacks and determine what to do with response

    Args:
        Response received from socket

    Returns:
        auth, soa, ns_count flags from received data

    """
    data = unpack(">6H", response[:12])
    flags = data[1]
    auth = hex(flags)[3]
    soa = hex(flags)[5]
    ns_count = data[4]
    return auth, soa, ns_count
    

def find(server, hostname, mx, root, count):
    """
    Recursive function used to resolve hostnames

    Args:
        Server - the next server to search
        Hostname - the hostname to resolve
        MX - flag for mail server
        root - list of root servers from root-servers.txt
        count - count of queries made

    Returns:
        Recursive find for next list of name servers, CNAME, or mail exchange
        Returns final IP address of resolved hostname
    """
    print("Querying " + server + "...")
    response = sendToServer(server, hostname, mx)
    # You'll need to unpack any response you get using the unpack function
    auth, soa, ns_count = parseResponse(response)
    type = findType(response)
    if soa == '3' or type == 6: #SOA
        if count == 0:
            return 'Invalid TLD'
        elif count == 1:
            return 'Invalid domain'
        else:
            return 'Subdomain could not be resolved, SOA'
    elif type == 5:
        cname = findCname(response)
        return find(root, cname, mx, root, count+1)
    elif auth == '4':
        if mx == True:
            mailexchange = findMail(response)
            return find(root, mailexchange, False, root, count+1)
        return findAnswer(response, 1)
    else:
        nsList = createNS(response, ns_count)
        for nsname in nsList:
            return find(nsname, hostname, mx, root, count+1)
        
            


def main(argv=None):
    if argv is None:
        argv = sys.argv

    mx = False #MX FLAG
    hostname = ""

    if len(argv) < 2 or (len(argv) == 3 and argv[1] != "-m") or len(argv) > 3:
        print("Incorrect Usage.\nFor A record lookup use: python resolver.py 'hostname'")
        print("For MX lookup use: python resolver.py -m 'hostname'")
    elif len(argv) == 3:
        mx = True
        hostname = argv[2]
    else:
        hostname = argv[1]

    #Populate a collection of root DNS server IP addresses from root-servers.txt
    networkList = networkToList('root-servers.txt')
    for server in networkList:
        try :
            count = 0
            val = find(server, hostname, mx, server, count)
            if val is not False:
                if mx == True and len(val.split(' ')) <= 2:
                    print("The mail exchange for " + hostname + " resolves to: " + val)
                elif len(val.split(' ')) <= 2:
                    print("The name " + hostname + " resolves to: " + val)
                else:
                    print(val)
                break
        except:
            print("Hostname could not be resolved using " + server)    

if __name__ == "__main__":
    main()
