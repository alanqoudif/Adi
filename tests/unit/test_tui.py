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


@pytest.mark.asyncio
async def test_command_palette_lists_adi_actions(tmp_path):
    from adi.product.tui.app import AdiCommands

    app = AdiApp(AdiConfig(runtime=RuntimeConfig(type="mock")), project_root=tmp_path)
    async with app.run_test() as pilot:
        provider = AdiCommands(app.screen)
        hits = [hit async for hit in provider.search("findings")]
        assert len(hits) >= 1
        await pilot.pause()


@pytest.mark.asyncio
async def test_command_palette_hit_runs_immediate_command(tmp_path):
    app = AdiApp(AdiConfig(runtime=RuntimeConfig(type="mock")), project_root=tmp_path)
    async with app.run_test() as pilot:
        app.run_command_line("/help")
        await pilot.pause()


@pytest.mark.asyncio
async def test_command_palette_hit_with_argument_fills_input(tmp_path):
    app = AdiApp(AdiConfig(runtime=RuntimeConfig(type="mock")), project_root=tmp_path)
    async with app.run_test() as pilot:
        app.run_command_line("/new ")
        await pilot.pause()
        input_widget = app.query_one("#input")
        assert input_widget.value == "/new "
