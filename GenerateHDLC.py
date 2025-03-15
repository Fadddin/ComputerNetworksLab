import struct

# HDLC Frame Constants
FLAG = 0x7E  # HDLC Flag sequence
ADDRESS = 0x01  # Example Address field
CONTROL = 0x03  # Example Control field

# Function to calculate a simple CRC-16 (used as FCS in HDLC)
def calculate_crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return struct.pack('<H', crc)  # Returns little-endian CRC-16 (2 bytes)

# Function to generate an HDLC frame
def generate_hdlc_frame(data):
    frame = bytearray()
    
    # Add opening flag
    frame.append(FLAG)
    
    # Add Address field
    frame.append(ADDRESS)
    
    # Add Control field
    frame.append(CONTROL)
    
    # Add Data field
    frame.extend(data)

    # Calculate CRC (FCS) and append
    crc = calculate_crc16(data)
    frame.extend(crc)

    # Add closing flag
    frame.append(FLAG)

    return frame

# Function to print the HDLC frame in hexadecimal format
def print_frame(frame):
    print("\nGenerated HDLC Frame:")
    print(' '.join(f'{byte:02X}' for byte in frame))

# Main function to get user input
def main():
    user_input = input("Enter the data to be transmitted: ")
    data = user_input.encode('utf-8')  # Convert input to bytes

    # Generate HDLC frame
    hdlc_frame = generate_hdlc_frame(data)

    # Print the frame
    print_frame(hdlc_frame)

if __name__ == "__main__":
    main()