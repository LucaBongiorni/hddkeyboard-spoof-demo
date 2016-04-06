# hddkeyboard-spoof-demo
Example of spoofing keyboard on certain USB 3.0 AES-256 HDDs.

Security research by Colin O'Flynn.

This is a basic PoC for spoofing the Keyboard on a a Satechi Lockdown USB 3.0 AES-256 Protected device, where
the PCB is marked:
	
	   20111020 Ver A3.
	   SKY Digital Inc.

This isn't a complete attack script, as it doesn't auto-increment the password guess. Using this requires you to have
an Atmel SAMD21 Xplained board. Connect PB08 to SDA on the Lockdown main board, and PA09 to SCL.
		
See following ascii-art for pin definitions, looking at main PCB:
		
	    +---------------------------------------------+
	    |               |USB CONN|             1  2   |
	    |                                      3  4   |
	+---+                                      5  6   +---+
	|                                                     |
	+-----------------------------------------------------+
	          | SATA CONNECTOR HERE |
			
   	2 = GND 
	5 = SDA
	6 = SCL

This script waits for the drive to boot, and once it sees the polling start it will pretend to enter
a specific PIN code. To complete the attack you would need this code to simply drive the RESET pin on the device, and
increment the PIN guess.
	
Using the RESET pin bypasses the wait-state that otherwise makes it too slow to brute-force.
	
There's no output, as this assumes you are running the code in a debugger to view the status.
