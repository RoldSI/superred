# tests/test_channels/test_bus.py
import pytest
import asyncio
from superred.channels.bus import EventBus


class TestEventBus:
    @pytest.mark.asyncio
    async def test_single_subscriber(self):
        bus = EventBus[str]()
        rx = bus.subscribe()
        await bus.publish("hello")
        bus.close()
        items = [item async for item in rx]
        assert items == ["hello"]

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self):
        bus = EventBus[int]()
        rx1 = bus.subscribe()
        rx2 = bus.subscribe()
        await bus.publish(42)
        bus.close()
        items1 = [item async for item in rx1]
        items2 = [item async for item in rx2]
        assert items1 == [42]
        assert items2 == [42]

    @pytest.mark.asyncio
    async def test_close_ends_all(self):
        bus = EventBus[str]()
        rx1 = bus.subscribe()
        rx2 = bus.subscribe()
        bus.close()
        assert [item async for item in rx1] == []
        assert [item async for item in rx2] == []
