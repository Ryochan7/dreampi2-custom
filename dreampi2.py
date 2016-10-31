#!/usr/bin/env python

import serial
import os
import logging
import subprocess
import time
import sys
import sh
import time
import argparse

from datetime import datetime, timedelta

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
#COMM_SPEED = 115200
COMM_SPEED = 38400

dial_tone_wav = None
time_since_last_dial_tone = 0
dial_tone_counter = 0
sending_tone = False
dial_tone_enabled = False
use_mgetty = True
use_pon = False

def runPon():
    logging.info("Starting pon...\n")
    logging.info(subprocess.check_output(["sudo", "pon", "dreamcast"]))

def runMgetty():
    logging.info("Starting mgetty...\n")
    subprocess.Popen(['sudo', '/sbin/mgetty', '-s', "{}".format(COMM_SPEED), '-D', "/dev/{}".format(MODEM_DEVICE), "-m", "\"\" ATZ0 OK ATM0 OK ATH0 OK"],
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
        
# Write code to run as daemon when I'm not lazy.

def send_command(modem, command, timeout=30):
    final_command = "{}\r\n".format(command)
    final_command_encoded = final_command.encode()
    modem.write(final_command_encoded)
    modem.flush()
    logging.info(final_command.strip() + '\n')

    start = datetime.now()
    line = ""

    VALID_RESPONSES = ("OK", "ERROR", "CONNECT", "VCON")
    search = True
    while search:
        new_data = modem.readline()
        endofline = b'\n' in new_data
        #print("LINE {}\n".format(new_data))
        #line = line + new_data.decode()
        #print("LINE {}".format(new_data))
        line = line + new_data.decode("unicode_escape")
        #print("OK" == line.strip())
        if endofline:
            line = line.strip()

        #if (new_data):
        #    print("DATA FOUND: {}".format(new_data))
        #    print('\n' in new_data)
        # Partial match response in line. Only look for response
        # at the end of the line.
        if line and endofline:
            for response in VALID_RESPONSES:
                if response in line:
                    #logging.info("FOUND RESPONSE: BREAK")
                    logging.info(line + '\n')
                    line = ""
                    search = False
                    break

        if endofline:
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
    resetModem(modem)
    send_command(modem, "AT+FCLASS=8")  # Switch to Voice mode
    send_command(modem, "AT+VLS=1") # Go off-hook

    #if "--enable-dial-tone" in sys.argv:
    if dial_tone_enabled:
        print("Dial tone enabled, starting transmission...\n")
        send_command(modem, "AT+VSM=129,8000")
        send_command(modem, "AT+VTX") # Transmit audio (for dial tone)
        # Generate tone via modem. Only lasts 4 seconds.
        #send_command(modem, "AT+VTS=[440,350,400]")

    logging.info("Setup complete, listening...")

    return modem

def disconnectModem(modem):
    if modem and modem.isOpen():
        modem.close()
        #modem = None
        logging.info("Serial interface terminated.")

def resetModem(modem):
    # Clear input and output buffers
    modem.reset_input_buffer()
    modem.reset_output_buffer()

    # Send initial commands to modem
    send_command(modem, "ATZ0") # RESET
    send_command(modem, "ATE0") # Don't echo our responses
    send_command(modem, "ATM0") # Disable modem speaker

def read_dial_tone():
    global dial_tone_wav
    this_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
    dial_tone_path = os.path.join(this_dir, "dial-tone.wav")

    try:
        with open(dial_tone_path, "rb") as f:
            dial_tone = f.read() # Read the entire wav file
            dial_tone = dial_tone[44:] # Strip the header (44 bytes)
            dial_tone_wav = dial_tone
    except IOError as e:
        logging.warning("Could not find dial tone wav file. Tone generation not possible.")

def start_dial_tone(modem):
    global sending_tone, time_since_last_dial_tone, dial_tone_counter
    if dial_tone_wav:
        sending_tone = True
        #time_since_last_dial_tone = datetime.now() - timedelta(seconds=100)
        time_since_last_dial_tone = 0
        dial_tone_counter = 0

def stop_dial_tone(modem):
    global sending_tone
    if sending_tone:
        modem.write("\0{}{}\r\n".format(chr(0x10), chr(0x03)).encode())
        modem.flush()
        send_escape(modem)
        send_command(modem, "ATH0") # Go on-hook
        time.sleep(2)
        if use_pon:
            resetModem(modem)

        sending_tone = False

def send_escape(modem):
    #time.sleep(1.0)
    modem.write(b"+++")
    modem.flush()
    #time.sleep(1.0)

def update_dial_tone(modem):
    global time_since_last_dial_tone, dial_tone_counter
    now = datetime.now()
    if sending_tone and dial_tone_wav:
        # Keep sending dial tone
        BUFFER_LENGTH = 1000
        TIME_BETWEEN_UPLOADS_MS = (1000.0 / 8000.0) * BUFFER_LENGTH
        if time_since_last_dial_tone:
            milliseconds = (now - time_since_last_dial_tone).microseconds / 1000.0
        else:
            milliseconds = 0.0

        if not time_since_last_dial_tone or milliseconds >= TIME_BETWEEN_UPLOADS_MS:
                tonebytes = dial_tone_wav[dial_tone_counter:dial_tone_counter+BUFFER_LENGTH]
                dial_tone_counter += BUFFER_LENGTH
                if dial_tone_counter >= len(dial_tone_wav):
                    dial_tone_counter = 0

                #logging.info("Broadcast dial tone segment")
                modem.write(tonebytes)
                modem.flush()
                time_since_last_dial_tone = now

def main():
    global dial_tone_enabled
    #dial_tone_enabled = "--enable-dial-tone" in sys.argv

    graphic()
    
    modem = initModem()
    
    timeSinceDigit = None

    mode = "LISTENING"

    if dial_tone_enabled:
        read_dial_tone()
        if dial_tone_wav:
            start_dial_tone(modem)
        else:
            dial_tone_enabled = False
    
    while True:
        if mode == "LISTENING":
            #Put code to generate dial tone here if you can figure it out.
            
            if timeSinceDigit is not None:
                # Digits received, answer call
                now = datetime.now()
                delta = (now - timeSinceDigit).total_seconds()
                if delta > 3:
                    if dial_tone_enabled:
                        logging.info("\nStopping dial tone...\n")
                        stop_dial_tone(modem)

                    logging.info("Answering call...\n")

                    if use_mgetty:
                        logging.info("")
                        disconnectModem(modem)
                        runMgetty()
                        # Breifly wait while mgetty is starting.
                        time.sleep(5)
                        # Put line back off-hook
                        killMgetty()

                    elif use_pon:
                        if not dial_tone_enabled:
                            resetModem(modem)
                            send_command(modem, "ATH0")

                        time.sleep(4)
                        send_command(modem, "ATA")
                        time.sleep(2)
                        runPon()
                        time.sleep(1)
                        disconnectModem(modem)
                        time.sleep(1)

                    logging.info("Call answered!")
                    for line in sh.tail("-f", "/var/log/syslog", "-n", "10", _iter=True):
                        if mode == "LISTENING" and "remote IP address" in line:
                            logging.info("Connected!")
                            mode = "CONNECTED"
                        elif mode == "CONNECTED" and "Modem hangup" in line:
                            logging.info("Detected modem hang up, going back to listening")
                            time.sleep(5) # Give the hangup some time
                            timeSinceDigit = None
                            mode = "LISTENING"
                            modem.close()
                            modem = initModem() # Reset the mode
                            if dial_tone_enabled and dial_tone_wav:
                                start_dial_tone(modem)

                            break

            update_dial_tone(modem)
            tempchar = modem.read(1)
            char = tempchar.strip()
            if not char:
                continue

            if ord(char) == 16:
                #DLE character
                #This code translates the tone digits to strings
                try:
                    char = modem.read()
                    timeSinceDigit = datetime.now()
                    digit = int(char)
                    logging.info("{}".format(digit))
                except (TypeError, ValueError):
                    pass

    return 0


if __name__ == '__main__':
    logging.getLogger().setLevel(logging.INFO)
    logging.getLogger().addHandler(logging.StreamHandler())

    parser = argparse.ArgumentParser(description="Establish a PC-DC server connection")
    parser.add_argument("--enable-dial-tone", help="Generate dial tone on line", action="store_true", default=False)
    parser.add_argument("--use-mgetty", help="Use mgetty to make final connection. (Default)", action="store_true", default=False)
    parser.add_argument("--use-pon", help="Use pon to make final connection", action="store_true", default=False)
    args = parser.parse_args()

    if args.use_mgetty and args.use_pon:
        logging.error("Cannot specify mgetty and pon together. Exiting.")
        sys.exit(1)

    elif not args.use_mgetty and not args.use_pon:
        # Use mgetty by default
        args.use_mgetty = True

    dial_tone_enabled = args.enable_dial_tone
    use_mgetty = args.use_mgetty
    use_pon = args.use_pon

    sys.exit(main())

