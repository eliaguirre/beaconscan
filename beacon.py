# bananaLABS 06/04/17
DEBUG = False

import os
import sys
import struct
import pexpect
import uuid
import threading
import subprocess
import time
import bluetooth._bluetooth as bluez

__version__ = '1.0'



LE_META_EVENT = 0x3e
OGF_LE_CTL=0x08
OCF_LE_SET_SCAN_ENABLE=0x000C
EVT_LE_CONN_COMPLETE=0x01
EVT_LE_ADVERTISING_REPORT=0x02

class Beacon:
    minor = 0
    major = 0
    UUID  = 0
    txPower = 0
    rssi  = 0
    macAddress=""

    def __init__(self,pkt):
        report_pkt_offset = 0
        l=len(pkt)
        self.rssi, = struct.unpack("b", pkt[l-1:l])
        self.txPower, = struct.unpack("b", pkt[l-2:l-1])
        self.macAddress = self.__packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9]).upper()
        self.UUID = str(uuid.UUID(self.__returnstringpacket(pkt[report_pkt_offset -22: report_pkt_offset - 6]) ) ) .upper()
        self.major= self.__returnnumberpacket(pkt[report_pkt_offset -6: report_pkt_offset - 4])
        self.minor= self.__returnnumberpacket(pkt[report_pkt_offset -4: report_pkt_offset - 2]) 


    def __packed_bdaddr_to_string(self,bdaddr_packed):
        return ':'.join('%02x'%i for i in struct.unpack("<BBBBBB", bdaddr_packed[::-1]))

    def __returnstringpacket(self,pkt):
        myString = "";
        i=0;
        for c in pkt:
            myString +=  "%02x" %struct.unpack("B",pkt[i:i+1])[0]
            i+=1
        return myString

    def __returnnumberpacket(self,pkt):
        myInteger = 0
        multiple = 256
        i=0;
        for c in pkt:
            myInteger +=  struct.unpack("B",pkt[i:i+1])[0] * multiple
            i+=1;
            multiple = 1
        return myInteger 

    def distancia(self):
        if self.rssi == 0 :
            return -1.0;
        if self.txPower == 0 :
            return -1.0
        else:
            ratio=self.rssi*1.0/self.txPower;
            if ratio < 1.0:
                return ratio ** 10;
            else:
                acc =(0.89976) *( ratio ** 7.7095 )+0.111;
                return acc;


    def toString(self):
        return "MAC: {0} UUID: {1} MAJOR: {2}\t MINOR: {3}\t TXPOWER: {4}\t RSSI: {5}\t DISTANCIA: {6}".format(self.macAddress,self.UUID,self.major,self.minor,self.txPower,self.rssi,self.distancia())
    
    def __str__(self):
        return self.toString();


def getBLESocket(devID):
    return bluez.hci_open_dev(devID)

def returnstringpacket(pkt):
    myString = "";
    for i in range(len(pkt)):
        myString += "%02x" %struct.unpack("B",pkt[i:i+1])[0]
    return myString

def get_packed_bdaddr(bdaddr_string):
    packable_addr = []
    addr = bdaddr_string.split(':')
    addr.reverse()
    for b in addr:
        packable_addr.append(int(b, 16))
    return struct.pack("<BBBBBB", *packable_addr)

def packed_bdaddr_to_string(bdaddr_packed):
    return ':'.join('%02x'%i for i in struct.unpack("<BBBBBB", bdaddr_packed[::-1]))

def hci_enable_le_scan(sock):
    hci_toggle_le_scan(sock, 0x01)

def hci_disable_le_scan(sock):
    hci_toggle_le_scan(sock, 0x00)

def hci_toggle_le_scan(sock, enable):
    cmd_pkt = struct.pack("<BB", enable, 0x00)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)

def hci_le_set_scan_parameters(sock):
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)



class Scanner:
    isScanning=False;
    scanner=None;
    _hci=None;
    beacons=[];

    def __init__(self):
        pass;


    def start(self):
        t = threading.Thread(target=worker_scan, args=(self, ))
        self.isScanning=True;
        t.start();

    def enable(self,hci):
        self._hci=hci;
        self.sock = bluez.hci_open_dev(hci)
        hci_le_set_scan_parameters(self.sock);
        hci_toggle_le_scan(self.sock, True);
        #hci_enable_le_scan(self.sock)

    def disable(self):
        hci_disable_le_scan(self.sock);


    def nextBeacon(self):
        if(self.isScanning==False):
            raise Exception('Inicia primero')
        if len(self.beacons)==0 :
            return None;
        return self.beacons.pop(0);


    def stop(self):
        self.isScanning=False;

    def parse_events(self,loop_count=100):
        old_filter = self.sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
        flt = bluez.hci_filter_new()
        bluez.hci_filter_all_events(flt)
        bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
        self.sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )
        done = False
        results = []
        myFullList = []
        for i in range(0, loop_count):
            pkt = self.sock.recv(255)
            ptype, event, plen = struct.unpack("BBB", pkt[:3])
            if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
                i =0
            elif event == bluez.EVT_NUM_COMP_PKTS:
                i =0 
            elif event == bluez.EVT_DISCONN_COMPLETE:
                i =0 
            elif event == LE_META_EVENT:
                subevent, = struct.unpack("B", pkt[3:4])
                pkt = pkt[4:]
                if subevent == EVT_LE_CONN_COMPLETE:
                    le_handle_connection_complete(pkt)
                elif subevent == EVT_LE_ADVERTISING_REPORT:
                    num_reports = struct.unpack("B", pkt[0:1])[0]
                    report_pkt_offset = 0
                    for i in range(0, num_reports):
                        try :
                            b=Beacon(pkt)
                            myFullList.append(b)
                        except:
                            pass;
                    done = True
        self.sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )
        return myFullList

def worker_scan(scan):
    try:
        frame=[];
        while scan.isScanning:
                returnedList = scan.parse_events(1);
                for beacon in returnedList:
                	if(len(scan.beacons)>=30):
                    		scan.beacons.insert(len(scan.beacons),beacon);
                	else:
                    		scan.beacons.append(beacon);
        scan.disable();
        return None;
    except pexpect.TIMEOUT as timeout:
        scan.start();
    except Exception as inst:
        scan.disable();
        print("error en servicio de scan");
        print(type(inst));
        print(inst.args);
        print(inst);


################################################
#
#       U T I L S
#
#################################################
def parse_uuid(pkt):
    tam=len(pkt);
    u=pkt[tam-22 :tam-6]
    bytes=''
    for i in range(0, len(u)):
        bytes+=( chr( int (u[i], 16 ) ) );
    return str(uuid.UUID(bytes=bytes));


def parse_mac(pkt):
    u=pkt[7:13]
    mac=''
    for i in range(0, len(u)):
        mac+=u[len(u)-1-i]+":";
    return mac[:len(mac)-1];


def isBeacon(frame):
    try:
        return (frame[21]=="02" and frame[22]=="15" ) or (frame[18]=="02" and frame[19]=="15" );
	    #return  (frame[21]=="02" and frame[22]=="15" );
    except:
        return False;





def quit(s, code=0):
    if s is not None:
        print(s)
    sys.exit(code)

def print_help():
    help = """
Usage: beacon method [OPTIONS]
       httpstat scan | start
       httpstat version
Options:
  OPTIONS which are already used internally.
  -h --help     show this screen.
  -H --hci      set hci dev
  -n --count    number of beacons in scanner
  --version     show version.
"""[1:-1]
    print(help)


OPTION_DEV_HCI=0;
OPTION_NUM_BEACON=0;



def main():
    global DEBUG
    global OPTION_DEV_HCI
    global OPTION_NUM_BEACON
    args = sys.argv[1:]
    if not args:
        print_help()
        quit(None, 0);
    try:
        arg = 0
        while arg < len(args):
            opt=args[arg]
            if opt in ("-h", "--help"):
                print_help()
                quit(None, 0);
            elif opt == '-d':
                DEBUG = True;
            elif opt in ("-H", "--hci"):
                OPTION_DEV_HCI = int(args[arg+1]);
            elif opt in ("-n", "--count"):
                OPTION_NUM_BEACON = int(args[arg+1]);
            arg += 1
    except Exception as inst:          
        #print_help()
        print(type(inst));
        print(inst.args);
        print(inst);
        print("error parse argumends")
        quit(None, 2);
    try:
        print("ble thread started")
        scanner = Scanner();
        scanner.enable(OPTION_DEV_HCI)
        scanner.start();
    except Exception as inst:
        print(type(inst));
        print(inst.args);
        print(inst);
        print("error accessing bluetooth device...")
        sys.exit(1)
    count=0;
    while count < OPTION_NUM_BEACON || OPTION_NUM_BEACON == 0:
        try :
            beacon=scanner.nextBeacon();
            if beacon is not None:
                print(beacon);
                count+=1;
        except KeyboardInterrupt:
            print("TERMINANDO POR EL TECLADO");
            scanner.stop();
            raise
        except Exception as inst:
            scanner.stop();
            print(inst);
            print("TERMINANDO POR OTRO ERROR")
            sys.exit(1);
    print("done");
    scanner.stop();




if __name__ == '__main__':
    main()


########### E N D ##############################


