'''
FIAP Checkpoint 01 - CODING FOR SECURITY
Leonardo Dalantonia Poloni (github.com/undeadwarlock) 
GPL3.0-or-foward
Version 1.0

Features pedidas no Checkpoint
[1] Verificar todas portas abertas do host  -> Feito em todas opções de SCAN
[2] Verificar o localhost                   -> opção -l/--localhost adiciona o localhost à pool de hosts
[3] Verificar o Sistema Operacional do Host (-o ou --os) -> opção -o pega o SO através de um regex no banner
[4] Verificar se há servidor WEB na 80/443 (-y ou --web) -> feito através de detecção da string HTTP no banner
[5] Tipos de SCAN:
5.0 - FULL TCP SCAN       -> -t
5.1 - STEALTH SCAN        -> -s
5.2 - NULL SCAN           -> -n
5.3 - FYN SCAN            -> -f
5.4 - XMAS SCAN           -> -x
5.5 - ACK SCAN            -> -a
5.6 - ACK WINDOW SIZE VALUE SCAN -> -w
5.7 - UDP SCAN        -> -u
[6] Features extras além dos tipos de scans:
6.0 -> Threads para aumentar a velocidade
6.1 - Verbose         (-v/--verbose) 
6.2 - Banner Grabbing (-b/--banner)
6.3 - IPv6            (-i/--ipv6)
6.4 - O parãmetro -p, onde deve ser inputado as portas, aceita 4 tipos de sintaxe (Podem ser combinados, com excessão da sintaxe D)
A- 1 valor de porta qualquer
B- Mais de um valor de porta, desde que separadas por vírgula -> 80,443,8080
C- Ranges de Portas  -> 1-14214
D- Um arquivo contendo uma porta escrita por linha
6.5 - O parâmetro -r, onde deve ser inputado o host alvo aceita os tipos de sintaxe:
A- Valor URL
B- Valor IPv6 (caso -i seja usado depois também)
C- Net IDs que também devem ser scaneados, escritos após um IPv4 -> 192.168.0.1,2,3,4 scaneia  1, 2, 3 e 4.
D- Ranges de NET IDs, escritos após um IPv4 -> 192.168.0.1,20-40    -> scaneia o host id 1 e do 20 a0 40. 
Pode ser usado C com D, como: 192.168.0.1,2,40-80   -> scan do host id 1,2 e do 40 ao 80. C e D só funcionam para IPv4.

EM DESENVOLVIMENTO PARA VERSÃO 2.0:
-d (--dump) para gerar o relatório do scanning
-c (--closed) para mostrar as portas fechadas
-o com uma potência maior que a atual visto que banner grabbing não é tao bom quanto TCP/IP Stack Fingerprinting para detecção de OS.

'''
from scapy.all import *
import threading 
import optparse
import pyfiglet 
import socket 
import re

screenLock = threading.Semaphore(value=1)  # ordenação das threads para que sejam printadas na ordem em que foram chamadas

def arguments():
    parser = optparse.OptionParser()
    
    parser.add_option("-r", "--host", dest= "host", help= "Target IP/Hostname. In /24 CIDR you can use Commas to add host ID (without the netid) to same subnet or use - between values to scan ranges. Input a txt if you rather write all desired IPs on a file. If IP is v6 you can only input a single address" )
    parser.add_option("-i", "--ipv6", dest= "ipv6", default= False, action="store_true", help= "Port Scanning of an IPv6 IP. Use -i and input the ipv6 address at -t")
    parser.add_option("-p", "--range", dest= "range", default=False, help= "Ports. 1 value = 1 port. Values after a comma are added and values like 10-30 are ranges. Input a txt if you rather write all IPs on a file. Not using -r will make the software scan ALL PORTS")
    parser.add_option("-l", "--localhost", dest= "localhost", default= False, action="store_true", help= "Scanned host will be localhost, which is a public ip")
    parser.add_option("-t", "--tcpscan", dest= "tcpscan", default= False, action= "store_true", help= "Triple Way Handshake") 
    parser.add_option("-s", "--stealthscan", dest= "stealthscan", default=False, action= "store_true", help= "SYN -> SYN/ACK -> Cancel three-way handshake")
    parser.add_option("-x", "--xmas", dest= "xmas", default=False, action="store_true", help= "TCP XMAS Scan" )
    parser.add_option("-a", "--ack", dest="ack", default=False, action="store_true", help= "TCP ACK Scan to detect Filtered Ports")
    parser.add_option("-n", "--null", dest= "null", default=False, action="store_true", help= "TCP Null Scan")
    parser.add_option("-f", "--fin", dest= "fin", default=False, action="store_true", help= "TCP Fin Scan")
    parser.add_option("-w", "--window", dest= "window", default=False, action="store_true", help = "TCP Rst Window Size Scan")
    parser.add_option("-u", "--udp", dest= "udp", default = False, action="store_true", help=" UDP Port Scanning")
    parser.add_option("-v", "--verbose", dest= "verbose", default=False, action="store_true", help= "Scapy Verbose. Select 1 or 0")
    parser.add_option("-y", "--web", dest="webserver", default=False, action="store_true", help="Check if a webserver is running at :80 or :443" )
    parser.add_option("-d", "--dump", dest="dump", default=False, action="store_true", help= "Logs the Scan Result")
    parser.add_option("-c", "--closed", dest="closed", default= False, action="store_true", help= "Show Closed Ports")
    parser.add_option("-b", "--banner", dest="banner", default= False, action="store_true", help= "Print the Banner grabbed with TCP FULL CONNECTION Scan")
    parser.add_option("-o", "--os", dest="os", default=False, action="store_true", help = "Try to get server/os information in a banner")
    (inputs, args) = parser.parse_args()
    
    if inputs.os or inputs.banner:
        inputs.tcpscan = True 

    if not inputs.range:
        parser.error("\n[X] Please input a port/range of ports or txt. If you selected -y the ports 80 and 443 are added, but you still need to add a port.")

    return (inputs.host, inputs.ipv6, inputs.range, inputs.localhost, inputs.tcpscan, inputs.stealthscan, inputs.xmas, inputs.ack, inputs.null, inputs.fin, inputs.window, inputs.udp, inputs.verbose, inputs.webserver, inputs.dump, inputs.closed, inputs.banner, inputs.os)

def getKnownPorts(): 
    '''
    Usa o arquivo services que vem na pasta do programa para saber quais serviços são comuns em cada porta estática.
    O resultado dessa função é usado depois por funções utilizadas pra printar o output.
    '''
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
    def __init__ (self, host, port, knownports=None, ipv6= None, verbose=None, checkweb= None, dump= None, closed= None, banner=None, os=None):
        self.checkweb = checkweb
        self.os  = [os, None]
        self.banner = banner
        self.host = host
        self.showclosed = closed
        self.dump = dump 
        try:
           self.hostEx = socket.gethostbyaddr(host)
        except:
           pass 
        self.port = port
        self.verbose = verbose
        self.knownports = knownports 
        self.scantype = str()
        self.closed = list()
        self.ipv6 = ipv6 

    def outputHeader(self, fullheader=None, hostheader=None):
        '''
        Header do Output, com algumas informações do HOST e o cabeçalho do output do programa.
        '''
        screenLock.acquire()   
        if fullheader:
           ascii_header = pyfiglet.figlet_format("PORT SCANNER")
           print(ascii_header)
        
        if hostheader:
           print("__"*38)
           print(f"Starting Scan on: {self.host}")
           try:
              print(f"HOST: {self.hostEx[0]}({self.hostEx[2][0]})")
              if self.hostEx[1]:
                 print(f"Alias: {self.hostEx[1]}")
           except:
               pass
           print("__"*38)
           print(f"PORT \t\tSTATE\t\tSERVICE\tSCANTYPE\t\tHOST ")
        screenLock.release()

    def associatePortToService(self, port):
        '''
        Usa o output da função getKnownPorts() do começo do programa para saber se a porta usada como parâmetro é conhecida.
        Dessa forma, ao se printar que a porta 80 está abertada (na função abaixo), ele também vai printar junto que a 80 é http.
        ''' 
        try:   
           for staticport in self.knownports:
               if re.match(f"{port}", staticport):
                   if re.match(f"{port}/udp", staticport) or re.match(f"{port}/tcp", staticport):
                       return [staticport, self.knownports[staticport]] #[port, service]
        except:
            pass
    
    def outputBody(self, port, state):
        '''
        Função para printar as portas abertas inputadas de um jeito que combine com o cabeçalho.
        '''         
        try:
            openport, service = self.associatePortToService(port)
            print(f"{openport}\t\t{state}\t{service}\t{self.scantype}\t\t{self.host}")
        except: 
            print(f"    {port}\t\t{state}\t?\t    {self.scantype}\t\t{self.host}")

    # def getOS(self):

    def checkWebServer(self, banner, port):
       '''
        Função pedida de checar WebServer nas portas 80,443.

        Se uma dessas portas está aberta, a função avisa.
        Se houver a string/substring HTTP no Banner ele também confirma que, com certeza, há um servidor WEB nessas portas.
       '''   
       if self.checkweb and port in [80,443]:
          print(f"[!] WEB Server Port:{port} is OPEN\n")
         
          if b"HTTP" in banner:
             print(f"[!] WEB Service Detected at {port}\n")

       return 


    def tcpfullscan(self):
        '''
        Three-way Handshake Scan.
        '''
        self.scantype = "FullTCP"
        try:
            if self.ipv6:
                conn = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
            conn.settimeout(2) 
            conn.connect((self.host, self.port)) 
            screenLock.acquire()                     
            self.outputBody(self.port, "OPEN          ")
            conn.send(b"FABIO PIRES LINUX")    # Manda uma mensagem pra pegar o banner
                                   
        except:
           pass 

        finally:
           try:
               
                  getbanner = conn.recv(100)    
                  if len(getbanner) != 0:
                        if self.os[0]:
                           self.os[1] = re.findall(b"Server: (.*)\\r\\n", getbanner)[0].decode("ascii")
                           print(f"Server/OS: {self.os[1]}\n")
                        if self.banner:
                           print(self.banner)
                           print()
                           print(getbanner.decode("ascii"))
                           print()
                           self.checkWebServer(getbanner, self.port)
           except:
                pass
           conn.close()
           screenLock.release()

    def stealthscan(self):
        '''
        Scan "Stealth"
        
        Envio de um pacote TCP/IP com a flag SYN.
        Caso a porta está aberta, recebe um SYN+ACK (flag 0x12).
        Nesse caso, o programa saberá que está aberta e responderá um RST para não terminar o Three-Way Handshake, o que o torna um scan mais furtivo que outros.
        
        Caso a porta está fechada, recebe apenas um RST (flag 0x14)
        Nesse caso, o programa saberá que a porta está fechada e nada precisa ser feito

        Se houver resposta com camada ICMP com os atributos type == 3 (INDICANDO ERRO DE UNREACHABLE) com code 1,2,3,9,10 ou 13 há a presença de filtros na rede, como firewall.
        
        '''
        # FAZER UM TRY EXCEPT COM LOOP CASO EU DESCUBRA QUE SPORT = 0 NAO EH PORT RANDOM FREE
        self.scantype = "stealth"
        
        if self.ipv6:
           ip_packet  = IPv6 (dst= self.host)
        else:
           ip_packet  = IP (dst= self.host)
        tcp_packet = TCP(dport= self.port, flags="S")
        tcp_ip = ip_packet/tcp_packet

        screenLock.acquire()

        stealth_scan = sr1(tcp_ip, timeout= 10)           # Envio do pacote utilizando SR1, pois só quero receber 1 pacote de resposta. O SR recebe todos.     
        if stealth_scan == None:                          # Se o pacote sucedeu, mas não houve resposta, há um Firewall Filtrando
            self.outputBody(self.port, "FILTERED      ")
        else:   
           if stealth_scan.haslayer(TCP):          # Checando se a resposta  veio com pacote TCP
               if stealth_scan.getlayer(TCP).flags == 0x12:   # Checando se houve resposta SYN + ACK ao meu SYN
                  self.outputBody(self.port, "OPEN          ")         # Se houve, printo que está aberto
                  rst = sr1(ip_packet/TCP(sport= self.port, dport= self.port, flags="R"), timeout= 0.5)   # Respondo o SYN + ACK com RST para não finalizar o Handshake triplo
               if stealth_scan.getlayer(TCP).flags == 0x14:  # Checando se a resposta ao SYN foi RST
                  self.closed = self.port               # Se sim, é porque a porta está fechada, então armazenarei no atributo de portas fechadas.
           if stealth_scan.haslayer(ICMP):         # Checando se há protocolo ICMP envolvido no pacote
               if int(stealth_scan.getlayer(ICMP).type) == 3 and int(stealth_scan.getlayer(ICMP).code) in [1,2,3,9,10,13]:  # erro 3 (UNREACHABLE), junto com certo valor de code é porque está filtrada
                   self.outputBody(self.port, "FILTERED     ")

        screenLock.release()

    def xmasscan(self):
        '''
        Envio de um TCP/IP com as flags: PSH, FIN e URG. 
        Em caso de não resposta, é porque a porta está aberta ou filtrada.
        Em caso de respost RST, a porta está fechada.
        Assim como nos outros scans, a análise do pacote ICMP, caso presente, pode indicar presença de Firewall.

        '''
        self.scantype = "XMAS"

        if self.ipv6:
           ip_packet  = IPv6 (dst= self.host)
        else:
           ip_packet  = IP (dst= self.host)
        tcp_packet = TCP(dport= self.port, flags= "FPU")      # pacote TCP com as flags FYN, PSH e URG
        tcp_ip = ip_packet/tcp_packet
        xmas_scan  = sr1(tcp_ip, timeout= 10)

        screenLock.acquire()

        if xmas_scan == None:                              # SEM RESPOSTA -> OPEN OU FILTERED
            self.outputBody(self.port, "OPEN or FILTER")
        else:
            if xmas_scan.haslayer(TCP):
               if xmas_scan.getlayer(TCP).flags == 0x14:      # Resposta RST -> PORTA FECHADA
                  self.closed = self.port
            if xmas_scan.haslayer(ICMP):
               if int(xmas_scan.getlayer(ICMP).type) == 3 and int(xmas_scan.getlayer(ICMP).code) in [1,2,3,9,10,13]: # assim como explicado no stealth scan, são valores que indicam filter
                   self.outputBody(self.port, "FILTER")

        screenLock.release()

    def finscan(self):
        '''
        Envio de um TCP/IP com a flag: FIN.
        Em caso de não resposta, porta está ABERTA.
        Em caso de resposta RST, porta está FECHADA.
        Assim como nos outros scans, a análise do pacote ICMP, caso presente, pode indicar filtragem de rede.
        '''
        self.scantype = "FIN"

        if self.ipv6:
           ip_packet  = IPv6 (dst= self.host)
        else:
           ip_packet  = IP (dst= self.host)
        tcp_packet = TCP(dport= self.port, flags="F")
        tcp_ip = ip_packet/tcp_packet 
        fin_scan   = sr1(tcp_ip, timeout=10)

        screenLock.acquire()

        if fin_scan == None:
            self.outputBody(self.port, "OPEN or FILTER")
        else:
           if fin_scan.haslayer(TCP):
               if fin_scan.getlayer(TCP).flags == 0x14: 
                   self.closed = self.port 
           if fin_scan.haslayer(ICMP):
               if int(fin_scan.getlayer(ICMP).type) == 3 and int(fin_scan.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                   self.outputBody(self.port, "FILTER        ")

        screenLock.release()

    def nullscan(self):
        '''
        Envio de um TCP/IP sem nenhuma flag.
        Sem resposta -> Porta Aberta
        Resposta RST -> Porta Fechada
        Assim como nos outros scans, a análise de um pacote ICMP, caso presente, pode indicar filtros de rede (firewalls)
        '''
        self.scantype = "NULL"

        if self.ipv6:
           ip_packet  = IPv6 (dst= self.host)
        else:
           ip_packet  = IP (dst= self.host)
        ip_packet = IP (dst= self.host) 
        tcp_packet= TCP(dport= self.port, flags='')
        tcp_ip = ip_packet/tcp_packet
        null_scan = sr1(tcp_ip, timeout=10)

        screenLock.acquire()

        if null_scan == None:
            self.outputBody(self.port, "OPEN or FILTER")
        else:
            if null_scan.haslayer(TCP):
               if null_scan.getlayer(TCP).flags == 0x14:
                   self.closed=self.port 
            if null_scan.haslayer(ICMP):
              if int(null_scan.getlayer(ICMP).type) == 3 and int(null_scan.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                 self.outputBody(self.port, "FILTER        ")

        screenLock.release()
    
    def tcpackscan(self):
        '''
        Envio de um TCP/IP com flag ACK.
        O único objetivo é descobrir quais portas está filtrada ou não. Não diz se está fechada ou aberta.
        Se a resposta for um pacote TCP com RSP -> não está filtrado
        Sem resposta ou com a mesma resposta ICMP explicada nos outros scans -> Filtrado
        '''
        self.scantype = "ACK"

        if self.ipv6:
           ip_packet  = IPv6 (dst= self.host)
        else:
           ip_packet  = IP (dst= self.host)
        tcp_packet = TCP(dport= self.port, flags= "A")
        tcp_ip = ip_packet/tcp_packet
        tcp_ack_scan = sr1(tcp_ip, timeout=10)

        screenLock.acquire()

        if tcp_ack_scan == None:
            self.outputBody(self.port, "FILTER        ")
        else:
           if tcp_ack_scan.haslayer(TCP):
               if tcp_ack_scan.getlayer(TCP).flags == 0X4:
                   self.outputBody(self.port, "NO-FILTER     ")
           if tcp_ack_scan.haslayer(ICMP):
               if int(tcp_ack_scan.getlayer(ICMP).type) == 3 and int(tcp_ack_scan.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                   self.outputBody(self.port, "FILTER        ")

        screenLock.release()
    
    def tcp_window_scan(self):
        '''
        Envio de um TCP/IP com flag ACK.
        Porém, diferente do TCP_ACK_SCAN, esse verifica o tamanho do atributo WindowSize da stack TCP/IP pra determinar se porta está aberta.
        Verifica o Window Size do pacote com flag RST recebido. Se o valor > 0  está aberta.

        '''
        self.scantype = "WINDOW"
        if self.ipv6:
           ip_packet  = IPv6 (dst= self.host)
        else:
           ip_packet  = IP (dst= self.host)
        tcp_packet = TCP(dport=self.port, flags="A")
        tcp_ip = ip_packet/tcp_packet
        tcp_window_scan = sr1(tcp_ip, timeout=10)

        screenLock.acquire()

        '''if tcp_window_scan == None:
            self.outputBody(self.port, "UNKNOWN")'''
        
        if tcp_window_scan == None:
            self.outputBody(self.port, "FILTER        ")
        else:
           if tcp_window_scan.haslayer(TCP):
               if tcp_window_scan.getlayer(TCP).window > 0:
                   self.outputBody(self.port, "OPEN          ")
               else:
                   self.closed = self.port  

        screenLock.release()

    def udp_scan(self):
        '''
        Envio de um pacote UDP para a porta.
        Em caso de resposta UDP, está aberto.
        Em caso de resposta ICMP erro 3 (unreachable) e code 3 está fechado.
        Também pode haver resposta ICMP com indicações de firewall.

        '''
        self.scantype = "UDP"
        udp_packets = list()

        if self.ipv6:
           ip_packet  = IPv6 (dst= self.host)
        else:
           ip_packet  = IP (dst= self.host)
        udp_packet = UDP (dport= self.port)
        udp_ip = ip_packet/udp_packet

        screenLock.acquire()

        for num in range(3):            # Como a garantia de entrega do UDP é feita pela camada 07 (menos garantia), devemos capturar mais de 1 pacote pra ter certeza quanto ao scan.
            udp_packets.append(sr1(udp_ip, timeout=10))

        for response in udp_packets:
            if response != None: 
                if response.haslayer(UDP):
                    self.outputBody(self.port, "OPEN(UDP)     ")
                if response.haslayer(ICMP):
                    if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3:
                        self.closed = self.port
                    if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                        self.outputBody(self.port, "FILTER        ")

        screenLock.release()
    

def main():
    host, ipv6, port, localhost, tcpscan, stealthscan, xmas, ack, null, fin, window, udp, verbose, webserver, dump, closed, banner, os = arguments()
    
    try:
       socket.gethostbyaddr(host)
       hosts = [host]
    except:
        hosts = list()

    ports = list() 

    if webserver: 
        ports += [80,443]

    if not verbose:
        conf.verb = 0     # se o user nao pedir verbose, scapy verbose vai ser retirada

    
    if localhost:
         hosts += ["localhost"]

    if not ipv6:
       '''
       Nessa função, eu lido com inputs de IPv4 que sejam digitados no formato de range, como por exemplo 192.168.0.1-10 (scan do hostid 1 ao 10)
       Também lido com inputs de IPv4 que sejam digitados para serem adicionados, como por exemplo 192.168.0.2,6,7,9 (scan do hostid 2,6,7 e 9 da subnet)
       '''
       try:
          address, others = re.findall(r"([0-9]{1,3}[\.]?[0-9]{1,3}[\.]?[0-9]{1,3}[\.]?[0-9]{1,3})([,\-]?.*)", host)[0]  # Separar Address dos caracteres que uso pra range(-) ou soma(,)
          if others:  
             host_id_add = re.findall(r"[,](\w{1,3})", others)   # Localizando todos HOST_IDS que querem ser adicionados através do método (,)
             if host_id:
                for hostid in host_id_add: 
                   add_address = re.findall(r"(\w{1,3}.\w{1,3}.\w{1,3}.)\w{1,3}", address)[0] + hostid # NET ID + HOST ID detectado no input
                   if add_address not in hosts:
                       hosts += [add_address]
             host_id_range = re.findall(r"[.,]((\w{1,3})-(\w{1,3}))", others)    # Localizando todos ranges de IP digitados pelo User numa tupla (range, start do range, fim do range)
             if host_id_range:
                try:
                   for _,startrange, endrange in host_id_range: 
                       for value in range(int(startrange), int(endrange) + 1):           # Pegando todos host ids do range
                           add_address = re.findall(r"(\w{1,3}.\w{1,3}.\w{1,3}.)\w{1,3}", address)[0] + str(value)  # Adicionando net id + host id pra cada host id do range
                           if add_address not in hosts:
                               hosts += [add_address]
                except:
                   pass
       except:
          pass

    try:                       # Verificação se o user inputou um arquivo contendo os hosts ao invés de digitar diretamente. Caso o Try não falhe, é porque sim.
        with open(host, "r") as readfile:
            readhosts = readfile.read().splitlines()      # Listagem de todos hosts escritos no arquivo
        for hostvalue in readhosts:
            if hostvalue not in hosts:
               hosts += [hostvalue]
    except:
        pass

    
    range_ports = re.findall(r"[.,]?((\w{1,5})-(\w{1,5}))", port)   # Localizando todos ranges de portas digitados pelo User na tupla (range, start, end)
    if range_ports:                                                # Se há range, entao prossiga
        try:
            for _,srange, erange in range_ports:                   # tupla (range, start, end)
                for item in range(int(srange), int(erange) +1):
                    if item not in ports:
                       ports += [item]
        except:
            pass
    

    add_ports = re.findall(r"[,]?(\w{1,3})", port)
    if add_ports:
        add_ports = [int(portt) for portt in add_ports if int(portt) not in ports]
        ports += add_ports

    if len(ports) == 0:    
       try:                 # Verificação se o input no parâmetro -r (portas) é um arquivo. Caso o try não falhe, há a leitura do arquivo em busca de portas escritas lá.
           with open(port, "r") as readfile:
               readports = readfile.read().splitlines()
           for portvalue in readports:
               if portvalue not in ports:
                  ports += [int(portvalue)]
       except:
           pass

    if port == False:
        ports = [element for element in range(1,65536)]

    knownports = getKnownPorts()

    PortScanner(hosts[0],0,0).outputHeader("FULL_HEADER","HOST_HEADER")    
    if stealthscan:
        for target in hosts:
            scan = PortScanner(target, 0, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
            for value in ports:
              scan = PortScanner(target, value, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
              t = threading.Thread(target= scan.stealthscan)
              t.start()

    if xmas:
        for target in hosts:
            scan = PortScanner(target, 0, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
            for value in ports:
              scan = PortScanner(target, value, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
              t = threading.Thread(target= scan.xmasscan)
              t.start()

    if ack:
        for target in hosts:
            scan = PortScanner(target, 0, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
            for value in ports:
              scan = PortScanner(target, value, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
              t = threading.Thread(target= scan.tcpackscan)
              t.start()
    
    if null:
        for target in hosts:
            scan = PortScanner(target, 0, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
            for value in ports:
              scan = PortScanner(target, value, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
              t = threading.Thread(target= scan.nullscan)
              t.start()

    if fin:
        for target in hosts:
            scan = PortScanner(target, 0, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
            for value in ports:
              scan = PortScanner(target, value, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
              t = threading.Thread(target= scan.finscan)
              t.start()

    if window:
        for target in hosts:
            scan = PortScanner(target, 0, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
            for value in ports:
              scan = PortScanner(target, value, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
              t = threading.Thread(target= scan.tcp_window_scan)
              t.start()

    if udp:
        for target in hosts:
            scan = PortScanner(target, 0, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
            for value in ports:
              scan = PortScanner(target, value, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
              t = threading.Thread(target= scan.udp_scan)
              t.start()

    if tcpscan:
        for target in hosts:
            scan = PortScanner(target, 0, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
            for value in ports:
              scan = PortScanner(target, value, knownports, ipv6, verbose, webserver, dump, closed, banner, os)
              t = threading.Thread(target= scan.tcpfullscan)
              t.start()
    




   # FAZER UM PRINT DE HOST POR MÉTODO

if __name__ == "__main__":
    main()

   


'''
ARRUMAR EXCEPTION 
TIRAR O DUPLO FOR POIS ESTÁ ENVIANDO TUDO DE NOVO ESSAS PORRAS 
'''






     



    



