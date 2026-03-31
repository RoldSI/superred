# tests/test_types/test_event.py
import pytest
from superred.types.event import (
    Event, EventResponse, ControllablePreCallEvent, ControllablePostCallEvent,
    ControllableInjection, PassThrough, OptimizerDoneEvent,
)
from superred.types.security import SecurityDomainTag
from superred.types.controllable import ControllableSpec


class TestEvent:
    def test_auto_id_and_timestamp(self):
        e = Event()
        assert isinstance(e.event_id, str)
        assert len(e.event_id) > 0
        assert e.security_domain is None

    def test_unique_ids(self):
        e1 = Event()
        e2 = Event()
        assert e1.event_id != e2.event_id

    def test_with_security_domain(self):
        tag = SecurityDomainTag(name="user")
        e = Event(security_domain=tag)
        assert e.security_domain is tag

    def test_frozen(self):
        e = Event()
        with pytest.raises(AttributeError):
            e.event_id = "x"


class TestControllablePreCallEvent:
    def test_fields(self):
        tag = SecurityDomainTag(name="external")
        spec = ControllableSpec(name="search", security_domain=tag)
        e = ControllablePreCallEvent(controllable=spec, request="query")
        assert e.controllable is spec
        assert e.request == "query"
        assert isinstance(e.event_id, str)


class TestControllablePostCallEvent:
    def test_fields(self):
        tag = SecurityDomainTag(name="external")
        spec = ControllableSpec(name="search", security_domain=tag)
        e = ControllablePostCallEvent(controllable=spec, request="query", answer="result")
        assert e.answer == "result"


class TestEventResponse:
    def test_references_event(self):
        e = Event()
        r = EventResponse(event=e)
        assert r.event is e


class TestControllableInjection:
    def test_injection_value(self):
        e = Event()
        inj = ControllableInjection(event=e, value="injected payload")
        assert inj.value == "injected payload"
        assert inj.event is e


class TestPassThrough:
    def test_passthrough(self):
        e = Event()
        pt = PassThrough(event=e)
        assert pt.event is e


class TestOptimizerDoneEvent:
    def test_is_event(self):
        done = OptimizerDoneEvent()
        assert isinstance(done, Event)
