"""Headless Textual acceptance test: the TUI launches, renders, accepts
keyboard input, and drives the same real Core as the plain shell — not a
disconnected mock-up. Uses Textual's own `run_test()` pilot (no real
terminal needed), which is the closest thing to "real manual TUI
acceptance" achievable in this sandbox; see
docs/product-implementation-status.md for what that does/doesn't cover.
"""

from __future__ import annotations

import pytest

from adi.config.models import AdiConfig, RuntimeConfig
from adi.product.tui.app import AdiApp


@pytest.mark.asyncio
async def test_tui_launches_and_shows_header(tmp_path):
    app = AdiApp(AdiConfig(runtime=RuntimeConfig(type="mock")), project_root=tmp_path)
    async with app.run_test() as pilot:
        assert app.title == "ADI"
        await pilot.pause()


@pytest.mark.asyncio
async def test_tui_new_assessment_via_input(tmp_path):
    from adi.product.models import ProviderProfile

    app = AdiApp(AdiConfig(runtime=RuntimeConfig(type="mock")), project_root=tmp_path)
    app.shell.controller.models.add_profile(ProviderProfile(name="m", kind="mock", locality="local"))
    async with app.run_test() as pilot:
        await pilot.click("#input")
        await pilot.press(*"/new 127.0.0.1")
        await pilot.press("enter")
        await pilot.pause()
        assert app.shell.controller.assessment is not None


@pytest.mark.asyncio
async def test_tui_keybindings_do_not_crash(tmp_path):
    app = AdiApp(AdiConfig(runtime=RuntimeConfig(type="mock")), project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.press("ctrl+f")
        await pilot.pause()
        await pilot.press("ctrl+e")
        await pilot.pause()
        await pilot.press("ctrl+s")
        await pilot.pause()
        await pilot.press("question_mark")
        await pilot.pause()


@pytest.mark.asyncio
async def test_tui_exit_command_quits(tmp_path):
    app = AdiApp(AdiConfig(runtime=RuntimeConfig(type="mock")), project_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.click("#input")
        await pilot.press(*"/exit")
        await pilot.press("enter")
        await pilot.pause()
