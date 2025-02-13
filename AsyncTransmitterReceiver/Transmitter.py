import asyncio


HOST = '127.0.0.1'
PORT = 8888


def compute_parity(bits):

    return sum(bits) % 2

async def transmitter():

    reader, writer = await asyncio.open_connection(HOST, PORT)
    data = input("Enter message to transmit: ")
    transmitted_data = []
    
    for char in data:
        bits = [int(b) for b in format(ord(char), '08b')]
        parity_bit = compute_parity(bits)
        frame = [1] + bits + [parity_bit, 0]  # Start bit, data, parity, stop bit
        transmitted_data.append(frame)
        
    message = str(transmitted_data).encode()
    writer.write(message)
    await writer.drain()
    # print("Data transmitted to server.")
    writer.close()
    await writer.wait_closed()


async def main():
    await transmitter()

if __name__ == "__main__":
    while(1 == 1):
        asyncio.run(main())