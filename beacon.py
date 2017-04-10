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

__version__ = '1.0'

class Beacon:
    minor = 0
    major = 0
    UUID  = 0
    txPower = 0
    rssi  = 0
    macAddress=""
    tipo=None

    def __init__(self,pkt,tipo="BEACON"):
        tam=len(pkt);
        self.minor=int("{0}{1}".format(pkt[tam-4],pkt[tam-3]), 16);
        self.major=int("{0}{1}".format(pkt[tam-6],pkt[tam-5]), 16);
        if tipo=="BEACON":
            self.txPower=int("{0}".format(pkt[tam-2]), 16)-256;
        else :
            self.txPower=-73;
        self.rssi=int("{0}".format(pkt[tam-1]), 16)-256;
        self.UUID=parse_uuid(pkt);
        self.macAddress=parse_mac(pkt);
        self.tipo=tipo;

    def distancia(self) :
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
        return "{7}:: MAC: {0} UUID: {1} MAJOR: {2} MINOR: {3} TXPOWER: {4} RSSI: {5} DISTANCIA: {6}".format(self.macAddress,self.UUID,self.major,self.minor,self.txPower,self.rssi,self.distancia(),self.tipo)

    def __str__(self):
        return self.toString();



class Scanner:
    isScanning=False;
    scanner=None;
    _hci=None;
    beacons=[];

    def __init__(self):
        pass;


    def start(self):
        os.system("hcitool lescan --duplicates 1>/dev/null &");
        self.scanner=pexpect.spawn("hcidump --raw");
        t = threading.Thread(target=worker_scan, args=(self, ))
        self.isScanning=True;
        t.start();

    def enable(self,hci):
        self._hci=hci;
        if "raspberry" in os.popen("uname -a").readlines()[0]:
            pass;
        else :  
            pass;
        os.system("rfkill unblock bluetooth");
        os.system("hciconfig {0} up".format(hci))

    def disable(self):
        os.system("hciconfig {0} down".format(self._hci))


    def nextBeacon(self):
        if(self.isScanning==False):
            raise Exception('Inicia primero')
        if len(self.beacons)==0 :
            return None;
        return self.beacons.pop(0);


    def stop(self):
        self.isScanning=False;


def worker_scan(scan):
    print "iniciando scan"
    try:
        frame=[];
        while scan.isScanning:
                line=scan.scanner.readline();
                if ">" in line: #es el inicio de un frame de beacon.
                        if len(frame)!=0 :
                                b=None;
                                try : 
                                    if isBeacon(frame):
                                        b=Beacon(frame);
                                    if b != None:
                                        if "007874ed-6da7-9862" in b.UUID:
                                            b.tipo="VIRTUAL";
                                        if "12:3B:6A" in b.macAddress:
                                            b.tipo="PULSERA";
                                    	if(len(scan.beacons)>=30):
                                        		scan.beacons.insert(len(scan.beacons),b);
                                    	else:
                                        		scan.beacons.append(b);
                                except :
                                    pass;
                                frame=[];
                        frame =line.replace(">","").replace("\n","").replace("\r","").replace("  "," ").split(" ");
                        frame.pop(0);
                        frame.pop(len(frame)-1);
                else: 
                        if len(frame)!=0 :
                                other=line.replace("\n","").replace("\r","").replace("  "," ").split(" ");
                                other.pop(0);
                                other.pop(len(other)-1);
                                frame=frame+other;
        scan.disable();
        return None;
    except pexpect.TIMEOUT as timeout:
        scan.start();
    except Exception as inst:
        scan.disable();
        print "error en servicio de scan";
        print type(inst);
        print inst.args;
        print inst;


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
        #return (frame[21]=="02" and frame[22]=="15" ) or (frame[18]=="02" and frame[19]=="15" );
	return  (frame[21]=="02" and frame[22]=="15" );
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
  OPTIONS  any curl supported options, except for -w -D -o -S -s,
                which are already used internally.
  -h --help     show this screen.
  --version     show version.
"""[1:-1]
    print(help)



def main():
    args = sys.argv[1:]
    if not args:
        print_help()
        quit(None, 0)
    try:
        print "ble thread started"
        scanner = Scanner();
        scanner.enable("hci0")
        scanner.start();
    except Exception as inst:
        print type(inst);
        print inst.args;
        print inst;
        print "error accessing bluetooth device..."
        sys.exit(1)
    corriendo=True;
    while corriendo:
        try :
            beacon=scanner.nextBeacon();
            if beacon is not None:
                print("DETECTADO {0} \t {1} \t {2} ".format(beacon.minor,beacon.major,beacon.macAddress.lower()))
        except KeyboardInterrupt:
            corriendo=False;
            print "TERMINANDO POR EL TECLADO";
            scanner.stop();
            raise
        except Exception as inst:
            corriendo=False;
            scanner.stop();
            print inst;
            print("TERMINANDO POR OTRO ERROR")
            sys.exit(1);
    print "Parando ciclo principal";
    scanner.stop();



if __name__ == '__main__':
    main()


########### E N D ##############################


