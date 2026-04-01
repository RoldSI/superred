from __future__ import annotations

from unittest.mock import patch

import pytest

from superred.registry.discovery import Registry


class TestRegistryDiscover:
    """Tests for Registry.discover and convenience methods."""

    def test_discover_optimizers_returns_dict(self) -> None:
        registry = Registry()
        result = registry.discover_optimizers()
        assert isinstance(result, dict)

    def test_discover_targets_returns_dict(self) -> None:
        registry = Registry()
        result = registry.discover_targets()
        assert isinstance(result, dict)

    def test_discover_tasks_returns_dict(self) -> None:
        registry = Registry()
        result = registry.discover_tasks()
        assert isinstance(result, dict)


class TestRegistryGet:
    """Tests for Registry.get."""

    def test_get_raises_key_error_for_unknown_module(self) -> None:
        registry = Registry()
        with pytest.raises(KeyError, match="not found"):
            registry.get("optimizers", "nonexistent_plugin")

    def test_get_raises_key_error_for_unknown_group(self) -> None:
        registry = Registry()
        with pytest.raises(KeyError, match="not found"):
            registry.get("unknown_group", "anything")


class TestRegistryListAll:
    """Tests for Registry.list_all."""

    def test_list_all_returns_dict_with_correct_keys(self) -> None:
        registry = Registry()
        result = registry.list_all()
        assert isinstance(result, dict)
        assert set(result.keys()) == {"optimizers", "targets", "tasks"}

    def test_list_all_values_are_sorted_lists(self) -> None:
        registry = Registry()
        result = registry.list_all()
        for names in result.values():
            assert isinstance(names, list)
            assert names == sorted(names)


class TestRegistryCaching:
    """Tests for Registry caching behaviour."""

    def test_second_call_returns_cached_result(self) -> None:
        registry = Registry()
        first = registry.discover("optimizers")
        second = registry.discover("optimizers")
        # Same object identity means the cache was used.
        assert first is second

    def test_cache_prevents_rescan(self) -> None:
        registry = Registry()
        with patch("superred.registry.discovery.importlib.metadata.entry_points") as mock_ep:
            mock_ep.return_value = []
            registry.discover("optimizers")
            registry.discover("optimizers")
            # entry_points should only be called once thanks to caching.
            mock_ep.assert_called_once()
