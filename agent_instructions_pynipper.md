# Gemini CLI Agent Instructions for pynipper-v2

## Project Overview
`pynipper-v2` is a multi-vendor network device parser and security analyzer. The project goal is to maintain parity with the original Nipper-ng tool while enabling modern device expansion.

## Core Mandates
1. **Architecture Fidelity**: Plugin-based architecture using `BaseDeviceParser` and `BasePlugin`.
2. **Comprehensive Testing**: Every added feature, parser, or security check must have corresponding unit/integration tests in `tests/` using `pytest`.
3. **Documentation**:
    - Update `CHANGELOG_AGENT.md` for all significant changes.
    - Maintain `docs/SUPPORTED_DEVICES.md` as the source of truth for device support.
4. **Git Workflow**: Do not perform automated git operations. Assume the user manages staging/committing.
5. **No Clutter**: Do not create temporary or phase-specific documentation. Keep the repository lean.

## Current Project Status
All initial parity and expansion phases are complete. The project is now in a maintenance and continuous improvement state.

## Operational Guidelines
- **Development Lifecycle**: Research -> Strategy -> Implementation -> Validation.
- **Validation**: Always run relevant tests before and after making changes.
- **Tone**: Professional, concise, senior engineering peer.
- **Tooling**: Use built-in tools over shell commands where possible.

## Maintenance
When adding a new device:
1. Create `src/devices/<vendor>/<device>.py`.
2. Create `src/analyze/<vendor>/plugins/<checks>.py`.
3. Add tests to `tests/test_<device>_plugin.py`.
4. Update `docs/SUPPORTED_DEVICES.md`.
5. Update `CHANGELOG_AGENT.md`.
