# tests/test_channels/test_channel.py
import pytest
import asyncio
from superred.channels.channel import channel, AsyncSender, AsyncReceiver, Channel, ChannelClosed


class TestChannel:
    @pytest.mark.asyncio
    async def test_send_recv(self):
        ch = channel[str]()
        await ch.sender.send("hello")
        msg = await ch.receiver.recv()
        assert msg == "hello"

    @pytest.mark.asyncio
    async def test_recv_nowait_empty(self):
        ch = channel[str]()
        result = ch.receiver.recv_nowait()
        assert result is None

    @pytest.mark.asyncio
    async def test_recv_nowait_has_item(self):
        ch = channel[str]()
        await ch.sender.send("x")
        result = ch.receiver.recv_nowait()
        assert result == "x"

    @pytest.mark.asyncio
    async def test_close_ends_iteration(self):
        ch = channel[int]()
        await ch.sender.send(1)
        await ch.sender.send(2)
        ch.sender.close()

        items = []
        async for item in ch.receiver:
            items.append(item)
        assert items == [1, 2]

    @pytest.mark.asyncio
    async def test_send_after_close_raises(self):
        ch = channel[str]()
        ch.sender.close()
        with pytest.raises(ChannelClosed):
            await ch.sender.send("x")

    @pytest.mark.asyncio
    async def test_buffered_channel(self):
        ch = channel[int](buffer=2)
        await ch.sender.send(1)
        await ch.sender.send(2)
        assert await ch.receiver.recv() == 1
        assert await ch.receiver.recv() == 2

    @pytest.mark.asyncio
    async def test_concurrent_send_recv(self):
        ch = channel[int]()
        results = []

        async def producer():
            for i in range(5):
                await ch.sender.send(i)
            ch.sender.close()

        async def consumer():
            async for item in ch.receiver:
                results.append(item)

        await asyncio.gather(producer(), consumer())
        assert results == [0, 1, 2, 3, 4]
