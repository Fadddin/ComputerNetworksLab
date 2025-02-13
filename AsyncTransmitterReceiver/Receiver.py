import asyncio

HOST = '127.0.0.1'
PORT = 8888

def compute_parity(bits):

    return sum(bits) % 2

async def handle_client(reader, writer):

    data = await reader.read(1024)
    transmitted_data = eval(data.decode())
    received_string = ""
    
    for frame in transmitted_data:
        start_bit, data_bits, parity_bit, stop_bit = frame[0], frame[1:9], frame[9], frame[10]
        
        if start_bit == 1 and stop_bit == 0:  # frame checkk
            if compute_parity(data_bits) == parity_bit:
                received_char = chr(int("".join(map(str, data_bits)), 2))
                received_string += received_char
            else:
                print("Parity error detected!")
    
    print(f"Final Received Message: {received_string}")
    writer.close()

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    print(f"Server started on {HOST}:{PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
