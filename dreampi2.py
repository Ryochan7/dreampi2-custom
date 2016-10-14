#!/usr/bin/env python

import serial
import os
import logging
import subprocess
import time
import sys
import sh
import time

from datetime import datetime

def graphic():
    print("     ____                            ____  _    ___  ")
    print("    / __ \________  ____  ____ ___  / __ \(_)  /__ \ ")
    print("   / / / / ___/ _ \/ __ `/ __ `__ \/ /_/ / /   __/ / ")
    print("  / /_/ / /  /  __/ /_/ / / / / / / ____/ /   / __/  ")
    print(" /_____/_/   \___/\__,_/_/ /_/ /_/_/   /_/   /____/  ")
    print(" RaspberryPi PC-DC Server Helper by Petri Trebilcock ")
    print("        Original idea/code by Luke Benstead          ")
    print("")

#MODEM_DEVICE = "ttyACM0"
MODEM_DEVICE = "ttyUSB0"
#COMM_SPEED = 230400
#COMM_SPEED = 57600
COMM_SPEED = 115200
#COMM_SPEED = 38400

def runPon():
    #time.sleep(2)
    subprocess.Popen(["sudo", "pon", "dreamcast"])
    #time.sleep(1)

def runMgetty():
    subprocess.Popen(['sudo', '/sbin/mgetty', '-s', "{}".format(COMM_SPEED), '-D', "/dev/{}".format(MODEM_DEVICE), "-m", "\"\" ATZ0 OK ATM0 OK ATH0 OK"],
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
        
# Write code to run as daemon when I'm not lazy.

def send_command(modem, command, timeout=30):
    final_command = "{}\r\n".format(command).encode()
    modem.write(final_command)
    modem.flush()
    logging.info(final_command)
    #time.sleep(0.5)

    #line = modem.readline()
    start = datetime.now()
    line = ""

    VALID_RESPONSES = ("OK", "ERROR", "CONNECT", "VCON")
    search = True
    while search:
        new_data = modem.readline()
        #print("LINE {}\n".format(new_data))
        #line = line + new_data
        #print("LINE {}".format(new_data))
        line = line + new_data
        #print("OK" == line.strip())
        line = line.strip()
        #if (new_data):
        #    print("DATA FOUND: {}".format(new_data))
        #    print('\n' in new_data)
        # Partial match response in line
        for response in VALID_RESPONSES:
            if response in line:
                #logging.info("FOUND RESPONSE: BREAK")
                logging.info(line)
                line = ""
                search = False
                break

        if '\n' in new_data:
            line = ""

        if (datetime.now() - start).total_seconds() >= timeout:
            raise IOError("There was a timeout while waiting for a response from the modem")

def killMgetty():
    subprocess.Popen(['sudo', 'killall', '-USR1', 'mgetty'])

def modemConnect():
    logging.info("Connecting to modem...:")
    
    #dev = serial.Serial("/dev/" + MODEM_DEVICE, 460800, timeout=0)
    dev = serial.Serial("/dev/" + MODEM_DEVICE, COMM_SPEED, timeout=0)
    
    logging.info("Connected.")
    return dev

def initModem():
    modem = modemConnect()

    # Send the initialization string to the modem
    send_command(modem, "ATZ0") # RESET
    send_command(modem, "ATE0") # Don't echo our responses
    #time.sleep(0.5)
    send_command(modem, "ATM0")
    #time.sleep(0.5)
    send_command(modem, "AT+FCLASS=8")  # Switch to Voice mode
    #time.sleep(0.5)
    send_command(modem, "AT+VLS=1") # Go online
    #time.sleep(0.5)

    if "--enable-dial-tone" in sys.argv:
        print("Dial tone enabled, starting transmission...")
        send_command(modem, "AT+VTX=1") # Transmit audio (for dial tone)

    logging.info("Setup complete, listening...")

    return modem

def main():
    
    graphic()
    
    modem = initModem()
    
    timeSinceDigit = None
    
    mode = "LISTENING"
    
    while True:
        if mode == "LISTENING":
            #Put code to generate dial tone here if you can figure it out.
            
            if timeSinceDigit is not None:
                #Digits received, answer call
                now = datetime.now()
                delta = (now - timeSinceDigit).total_seconds()
                if delta > 3:
                    logging.info("Answering call...")
                    runMgetty()
                    #send_command(modem, "ATZ0")
                    #send_command(modem, "ATM0")
                    #send_command(modem, "ATH0")
                    #time.sleep(4)
                    #send_command(modem, "ATA")
                    #runPon()
                    time.sleep(5)
                    killMgetty()
                    logging.info("Call answered!")
                    for line in sh.tail("-f", "/var/log/syslog", "-n", "10", _iter=True):
                        if mode == "LISTENING" and "remote IP address" in line:
                            logging.info("Connected!")
                            mode = "CONNECTED"
                        elif mode == "CONNECTED" and "Modem hangup" in line:
                            logging.info("Detected modem hang up, going back to listening")
                            time.sleep(10) # Give the hangup some time
                            timeSinceDigit = None
                            mode = "LISTENING"
                            modem.close()
                            modem = initModem() # Reset the modem
                            break
                        
            char = modem.read(1).strip()
            if not char:
                continue
            
            if ord(char) == 16:
                #DLE character
                #This code translates the tone digits to strings
                try:
                    char = modem.read()
                    digit = int(char)
                    timeSinceDigit = datetime.now()
                    print("{}".format(digit))
                except (TypeError, ValueError):
                    pass

    return 0


if __name__ == '__main__':
    logging.getLogger().setLevel(logging.INFO)
    logging.getLogger().addHandler(logging.StreamHandler())
    sys.exit(main())
