import asyncio
from websockets import serve

import packetstreamer

async def main() -> None:
    async def wsserve(websocket) -> None:
        streamer = packetstreamer.PacketStreamer()
        await streamer.send_skill_mapping(websocket)
        await streamer.stream(websocket)
    async with serve(wsserve, '0.0.0.0', 8080):
        print("WebSocket server started on ws://0.0.0.0:8080")
        await asyncio.Future()  # run forever

if __name__ == '__main__':
    asyncio.run(main())
    
