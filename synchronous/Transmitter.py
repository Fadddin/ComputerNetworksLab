import socket
import time

HOST = '127.0.0.1'
PORT = 8888
CLOCK_FREQ = 2  # 2 Hz clock (i.e., send 2 bits per second)
CLOCK_DELAY = 1 / CLOCK_FREQ

def compute_parity(bits):
    return sum(bits) % 2

def transmitter():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        data = input("Enter message to transmit: ")

        for char in data:
            bits = [int(b) for b in format(ord(char), '08b')]
            parity_bit = compute_parity(bits)
            frame = [1] + bits + [parity_bit, 0]  # Start bit, data, parity, stop bit

            print(f"Transmitting frame for '{char}': {frame}")

            for bit in frame:
                s.send(str(bit).encode())  # Send one bit (as a byte)
                print(f"Sent bit: {bit}")
                time.sleep(CLOCK_DELAY)    # Wait based on clock frequency

        print("Message sent.")

if __name__ == "__main__":
    while True:
        transmitter()
