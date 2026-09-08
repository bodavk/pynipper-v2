# Priority Order: Achieving Original Device Parity

The following list prioritizes the implementation of missing device parsers and checks from the original Nipper-ng. This ranking is based on modern production network relevance, vendor prevalence, and complexity of implementation.

| Rank | Task ID | Device / OS | Priority | File Path | Notes |
| :---: | :--- | :--- | :--- | :--- | :--- |
| 1 | `05_checkpoint_fw1` | CheckPoint Firewall-1 | **CRITICAL** | `docs\agent_notes\tasks\parity\05_checkpoint_fw1.md` | IMPLEMENTED |
| 2 | `03_juniper_screenos` | Juniper ScreenOS | **HIGH** | `docs\agent_notes\tasks\parity\03_juniper_screenos.md` | IMPLEMENTED |
| 3 | `04_sonicwall_sonicos` | SonicWALL SonicOS | **LOW** | `docs\agent_notes\tasks\parity\04_sonicwall_sonicos.md` | New priority: Low. |
| 4 | `02_hp_procurve` | HP ProCurve Switch | **LOW** | `docs\agent_notes\tasks\parity\02_hp_procurve.md` | New priority: Low. |

## Refactoring Recommendation

Before proceeding to implement non-Cisco devices (starting with Rank 1: CheckPoint), we **must** design a pluggable device parsing/loading architecture. The current codebase has no `BaseDevice` interface (as noted in `00_architecture_conventions.md`), and the core processing logic is tightly coupled to Cisco IOS formatting and `ciscoconfparse`.
