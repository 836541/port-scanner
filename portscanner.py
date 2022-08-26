'''
FIAP Checkpoint 01 - CODING FOR SECURITY
Leonardo Dalantonia Poloni (github.com/undeadwarlock) 
GPL3.0-or-foward
Version 1.0

Features pedidas no Checkpoint
[1] Verificar todas portas abertas do host -> Feito em todas opções de SCAN
[2] Verificar o localhost                  -> opção -l/--localhost
[3] Verificar o Sistema Operacional do Host
3.1 -> -b
3.2 -> -fingerprinting
[4] Verificar se há servidor WEB na 80/443
[5] Opções a mais adicionadas:
5.1 - STEALTH SCAN (SYN -> SYN/ACK -> RST)
5.2 - NULL SCAN 
5.3 - FYN SCAN
5.4 - XMAS SCAN
5.5 - AGGRO SCAN 
[6] Parâmetros extras:
6.1 - Verbose         (-v/--verbose) (print name)
6.2 - Banner Grabbing (-b/--banner)
Algumas funções para melhor funcionalidades
[1] - Parâmetro -h/--host suporta tanto hostname quanto address
Botar o gethostbyaddr no header



'''
import threading 
import optparse
import pyfiglet 
import socket 
import scapy 
import re

def arguments():
    parser = optparse.OptionParser()
    
    parser.add_option("-t", "--host", dest= "host", help= "Target IP/Hostname" )
    parser.add_option("-v", "--verbose", dest= "verbose", type = "int")
    parser.add_option("-l", "--localhost", dest= "localhost", default= False, action="store_true", help= "Scanned host will be localhost, which is a public ip")
    parser.add_option("-f", "--tcpscan", dest= "tcpscan", default= False, action= "store_true", help= "Triple Way Handshake") 
    parser.add_option("-s", "--stealthscan", dest= "stealthscan", default=False, action= "store_true", help= "SYN -> SYN/ACK -> Cancel three-way handshake")
    parser.add_option("-w", "--web", dest="webserver", default=False, action="store_true", help="Check if a webserver is running at :80 or :443" )
    parser.add_option("-d", "--dump", dest="dump", default=False, action="store_true", help= "Log Open Ports")
    (inputs, args) = parser.parse_args()

    return () 

def getKnownPorts():
    knownports = {}
    try:                   
        with open("services","r") as services:
                readfile = services.read().splitlines()
        for line in readfile:
                knownport = re.findall(r"((\w*)\s*([0-9]{1,5}/[a-z]{3}))", line)
                if knownport:
                    knownports[knownport[0][2]] = knownport[0][1]
    except:
            pass 

    return knownports

class PortScanner:
    def __init__ (self, host, port, knownports=None, verbose=None, checkweb= None, dump= None, showclosed= None):
        self.checkweb = checkweb
        self.host = host
        self.showclosed = showclosed
        self.hostEx = socket.gethostbyaddr(host)
        self.port = port
        self.verbose = verbose
        self.knownports = knownports 

    def outputHeader(self):    # HEADER DO OUTPUT 

        ascii_header = pyfiglet.figlet_format("PORT SCANNER")
        print("__"*38)
        print(ascii_header)
        print(f"Starting Scan on: {self.host}")
        print(f"HOST: {self.hostEx[0]}({self.hostEx[2][0]})")
        print("__"*38)
        if self.hostEx[1]:
            print(f"Alias: {self.hostEx[1]}")
        print(f"PORT \t STATE SERVICE ")

    def associatePortToService(self, port):     # ASSOCIA A PORTA COM UM SERVIÇO CONHECIDO NO OUTPUT
        for staticport in self.knownports:
            if re.match(f"{port}", staticport):
                if re.match(f"{port}/udp", staticport) or re.match(f"{port}/tcp", staticport):
                    return [staticport, self.knownports[staticport]] #[port, service]
    
    def outputBody(self, port):         # UTILIZA A FUNÇÃO ANTERIOR PRA PRINTAR AS PORTAS E SEUS SERVIÇOS
        try:
            openport, service = self.associatePortToService(port)
            print(f"{openport}  OPEN  {service}")
        except: 
            print(f"{openport}  OPEN")



    def checkWebServer(self, banner, port):   # CHECA PORTAS WEB E AVISA SE ESTÁ ABERTO E SE HÁ SERVIÇO DETECTADO NO BANNER
       if self.checkweb and port in [80,443]:
          print(f"[!] WEB Server Port:{port} is OPEN\n")
        
       if b"HTTP" in banner:
          print(f"[!] WEB Service Detected at {port}\n")

       return 


    def tcpfullscan(self):   # SCAN FULL HANDSHAKE
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
            conn.settimeout(2) 
            conn.connect((self.host, self.port))                      
            self.outputBody(self.port)
            conn.send(b"FABIO PIRES LINUX")
                                   
        except:
           pass 

        finally:
           try:
               getbanner = conn.recv(100)
               if len(getbanner) != 0:
                  print()
                  print(getbanner.decode("ascii"))
                  print()
                  self.checkWebServer(getbanner, self.port)
           except:
                pass
           conn.close()

    def 


    
    



if __name__ == "__main__":
   self.outputHeader()



   for port in range(66000):
       t = threading.Thread(target=tcpfullscan, args= ('44.209.21.146',port))
       t.start()   