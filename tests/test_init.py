# tests/test_init.py
def test_top_level_imports():
    from superred import (
        Target, Task, Optimizer, Judge, SecurityClaim,
        Event, EventResponse, Goal, Trajectory,
    )


def test_channel_imports():
    from superred.channels import channel, Channel, compose, EventBus
