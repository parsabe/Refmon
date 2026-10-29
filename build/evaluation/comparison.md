634 variants, identical event streams in both runs (hash checked).

**All variants of the seed**

| | v1.0 | v1.1 |
|---|---:|---:|
| variants | 634 | 634 |
| block | 446 | 487 |
| effective hold | 105 | 140 |
| uncontained | 83 | 7 |
| allow | 14 | 7 |
| hold pauses nothing | 69 | 0 |
| blocks that act on nothing | 11 | 9 |

**Seeded combinations (depend on the seed: the independent test)**

| | v1.0 | v1.1 |
|---|---:|---:|
| variants | 235 | 235 |
| block | 138 | 156 |
| effective hold | 55 | 75 |
| uncontained | 42 | 4 |
| allow | 9 | 4 |
| hold pauses nothing | 33 | 0 |
| blocks that act on nothing | 6 | 4 |

**Baselines, no-label and one-factor variants (the same for every seed: a regression check, not fresh evidence)**

| | v1.0 | v1.1 |
|---|---:|---:|
| variants | 399 | 399 |
| block | 308 | 331 |
| effective hold | 50 | 65 |
| uncontained | 41 | 3 |
| allow | 5 | 3 |
| hold pauses nothing | 36 | 0 |
| blocks that act on nothing | 5 | 5 |

**Variants whose outcome changed between versions: 114**

- allow -> block: 3
- allow -> effective hold: 4
- effective hold -> block: 38
- hold pauses nothing -> effective hold: 69

| variant | v1.0 | v1.1 | seeded |
|---|---|---|---|
| S01 combo-11 (delivery=typed, obfuscation=stripped) | hold pauses nothing | effective hold | yes |
| S01 combo-2 (delivery=typed, obfuscation=padded) | hold pauses nothing | effective hold | yes |
| S01 combo-6 (delivery=typed, timing=minutes) | hold pauses nothing | effective hold | yes |
| S01 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S02 combo-3 (delivery=typed, entry=run_dialog, lineage=2, timing=minutes) | hold pauses nothing | effective hold | yes |
| S02 combo-7 (entry=scheduled_task, obfuscation=high_entropy, timing=minutes) | effective hold | block | yes |
| S02 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S02 entry=file_manager (entry=file_manager) | effective hold | block | no |
| S02 entry=run_dialog (entry=run_dialog) | effective hold | block | no |
| S02 entry=scheduled_task (entry=scheduled_task) | effective hold | block | no |
| S02 entry=script_host (entry=script_host) | effective hold | block | no |
| S03 combo-3 (delivery=typed, entry=terminal, obfuscation=stripped, timing=minutes) | hold pauses nothing | effective hold | yes |
| S03 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S04 combo-12 (delivery=typed, destination=popular_trusted, timing=minutes) | hold pauses nothing | effective hold | yes |
| S04 combo-4 (delivery=opened, entry=run_dialog, obfuscation=stripped) | effective hold | block | yes |
| S04 combo-5 (delivery=typed, destination=internal_network) | hold pauses nothing | effective hold | yes |
| S04 combo-8 (entry=run_dialog, lineage=1) | effective hold | block | yes |
| S04 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S04 entry=file_manager (entry=file_manager) | effective hold | block | no |
| S04 entry=run_dialog (entry=run_dialog) | effective hold | block | no |
| S04 entry=scheduled_task (entry=scheduled_task) | effective hold | block | no |
| S04 entry=script_host (entry=script_host) | effective hold | block | no |
| S05 baseline (unmodified) | hold pauses nothing | effective hold | no |
| S05 combo-1 (lineage=4, obfuscation=stripped) | hold pauses nothing | effective hold | yes |
| S05 combo-10 (delivery=opened, entry=script_host, obfuscation=stripped) | hold pauses nothing | effective hold | yes |
| S05 combo-12 (entry=script_host, timing=minutes) | hold pauses nothing | effective hold | yes |
| S05 combo-2 (delivery=typed, destination=internal_network, obfuscation=stripped) | hold pauses nothing | effective hold | yes |
| S05 combo-3 (lineage=3, obfuscation=padded) | hold pauses nothing | effective hold | yes |
| S05 combo-4 (delivery=opened, destination=internal_network, entry=scheduled_task, obfuscation=high_entropy) | hold pauses nothing | effective hold | yes |
| S05 combo-5 (lineage=4, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S05 combo-6 (delivery=opened, entry=scheduled_task) | hold pauses nothing | effective hold | yes |
| S05 combo-7 (entry=terminal, lineage=4) | hold pauses nothing | effective hold | yes |
| S05 combo-8 (entry=script_host, lineage=2, obfuscation=padded, timing=minutes) | hold pauses nothing | effective hold | yes |
| S05 combo-9 (delivery=dragged, lineage=1) | hold pauses nothing | effective hold | yes |
| S05 delivery=dragged (delivery=dragged) | hold pauses nothing | effective hold | no |
| S05 delivery=opened (delivery=opened) | hold pauses nothing | effective hold | no |
| S05 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S05 destination=internal_network (destination=internal_network) | hold pauses nothing | effective hold | no |
| S05 destination=popular_trusted (destination=popular_trusted) | hold pauses nothing | effective hold | no |
| S05 entry=file_manager (entry=file_manager) | hold pauses nothing | effective hold | no |
| S05 entry=run_dialog (entry=run_dialog) | hold pauses nothing | effective hold | no |
| S05 entry=scheduled_task (entry=scheduled_task) | hold pauses nothing | effective hold | no |
| S05 entry=script_host (entry=script_host) | hold pauses nothing | effective hold | no |
| S05 entry=terminal (entry=terminal) | hold pauses nothing | effective hold | no |
| S05 lineage=1 (lineage=1) | hold pauses nothing | effective hold | no |
| S05 lineage=2 (lineage=2) | hold pauses nothing | effective hold | no |
| S05 lineage=3 (lineage=3) | hold pauses nothing | effective hold | no |
| S05 lineage=4 (lineage=4) | hold pauses nothing | effective hold | no |
| S05 obfuscation=high_entropy (obfuscation=high_entropy) | hold pauses nothing | effective hold | no |
| S05 obfuscation=padded (obfuscation=padded) | hold pauses nothing | effective hold | no |
| S05 obfuscation=stripped (obfuscation=stripped) | hold pauses nothing | effective hold | no |
| S05 timing=beyond_window (timing=beyond_window) | hold pauses nothing | effective hold | no |
| S05 timing=minutes (timing=minutes) | hold pauses nothing | effective hold | no |
| S06 combo-1 (delivery=dragged, entry=script_host, lineage=3, obfuscation=stripped) | effective hold | block | yes |
| S06 combo-3 (delivery=typed, lineage=4, obfuscation=padded, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S06 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S06 entry=file_manager (entry=file_manager) | effective hold | block | no |
| S06 entry=run_dialog (entry=run_dialog) | effective hold | block | no |
| S06 entry=scheduled_task (entry=scheduled_task) | effective hold | block | no |
| S06 entry=script_host (entry=script_host) | effective hold | block | no |
| S07 combo-1 (delivery=inbound_request, destination=internal_network, entry=script_host, lineage=4) | effective hold | block | yes |
| S07 combo-4 (delivery=typed, entry=file_manager, obfuscation=stripped) | hold pauses nothing | effective hold | yes |
| S07 combo-5 (delivery=typed, entry=file_manager, lineage=2) | hold pauses nothing | effective hold | yes |
| S07 combo-7 (destination=popular_trusted, obfuscation=stripped, timing=minutes) | allow | block | yes |
| S07 combo-8 (delivery=typed, lineage=2) | hold pauses nothing | effective hold | yes |
| S07 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S07 destination=popular_trusted (destination=popular_trusted) | allow | block | no |
| S07 entry=file_manager (entry=file_manager) | effective hold | block | no |
| S07 entry=run_dialog (entry=run_dialog) | effective hold | block | no |
| S07 entry=scheduled_task (entry=scheduled_task) | effective hold | block | no |
| S07 entry=script_host (entry=script_host) | effective hold | block | no |
| S12 combo-5 (entry=web_worker, lineage=3, obfuscation=stripped, timing=beyond_window) | effective hold | block | yes |
| S12 combo-6 (destination=internal_network, entry=file_manager, lineage=1, obfuscation=stripped) | hold pauses nothing | effective hold | yes |
| S12 entry=file_manager (entry=file_manager) | hold pauses nothing | effective hold | no |
| S12 entry=run_dialog (entry=run_dialog) | hold pauses nothing | effective hold | no |
| S13 combo-1 (destination=popular_trusted, timing=beyond_window) | effective hold | block | yes |
| S13 combo-2 (destination=popular_trusted, entry=script_host, obfuscation=stripped) | allow | effective hold | yes |
| S13 combo-3 (destination=internal_network, entry=file_manager, lineage=4) | hold pauses nothing | effective hold | yes |
| S13 combo-4 (entry=terminal, obfuscation=high_entropy, timing=beyond_window) | effective hold | block | yes |
| S13 combo-8 (entry=run_dialog, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S13 entry=file_manager (entry=file_manager) | hold pauses nothing | effective hold | no |
| S13 entry=run_dialog (entry=run_dialog) | hold pauses nothing | effective hold | no |
| S13 timing=beyond_window (timing=beyond_window) | effective hold | block | no |
| S15 combo-2 (destination=popular_trusted, timing=beyond_window) | effective hold | block | yes |
| S18 combo-3 (destination=popular_trusted, timing=minutes) | allow | effective hold | yes |
| S18 combo-5 (destination=popular_trusted, timing=beyond_window) | allow | effective hold | yes |
| S18 destination=popular_trusted (destination=popular_trusted) | allow | effective hold | no |
| S21 combo-4 (entry=run_dialog, lineage=2) | hold pauses nothing | effective hold | yes |
| S21 combo-7 (entry=run_dialog, timing=minutes) | hold pauses nothing | effective hold | yes |
| S21 entry=file_manager (entry=file_manager) | hold pauses nothing | effective hold | no |
| S21 entry=run_dialog (entry=run_dialog) | hold pauses nothing | effective hold | no |
| S25 combo-10 (entry=file_manager, lineage=4, obfuscation=high_entropy) | hold pauses nothing | effective hold | yes |
| S25 combo-12 (entry=file_manager, lineage=3) | hold pauses nothing | effective hold | yes |
| S25 combo-2 (lineage=4, timing=beyond_window) | effective hold | block | yes |
| S25 combo-3 (entry=run_dialog, obfuscation=high_entropy, timing=minutes) | hold pauses nothing | effective hold | yes |
| S25 combo-4 (destination=internal_network, entry=run_dialog, lineage=1) | hold pauses nothing | effective hold | yes |
| S25 combo-6 (entry=file_manager, lineage=3, obfuscation=high_entropy, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S25 combo-8 (lineage=1, timing=beyond_window) | effective hold | block | yes |
| S25 entry=file_manager (entry=file_manager) | hold pauses nothing | effective hold | no |
| S25 entry=run_dialog (entry=run_dialog) | hold pauses nothing | effective hold | no |
| S25 timing=beyond_window (timing=beyond_window) | effective hold | block | no |
| S26b combo-8 (destination=popular_trusted, timing=beyond_window) | effective hold | block | yes |
| S31 combo-10 (entry=file_manager, lineage=1, obfuscation=padded, timing=minutes) | hold pauses nothing | effective hold | yes |
| S31 entry=file_manager (entry=file_manager) | hold pauses nothing | effective hold | no |
| S31 entry=run_dialog (entry=run_dialog) | hold pauses nothing | effective hold | no |
| S31 timing=beyond_window (timing=beyond_window) | effective hold | block | no |
| S32 combo-10 (destination=popular_trusted, entry=terminal, obfuscation=stripped, timing=beyond_window) | effective hold | block | yes |
| S32 timing=beyond_window (timing=beyond_window) | effective hold | block | no |
| S33 timing=beyond_window (timing=beyond_window) | effective hold | block | no |
| S34 combo-3 (lineage=3, timing=beyond_window) | effective hold | block | yes |
| S34 combo-5 (delivery=inbound_request, lineage=4, obfuscation=stripped, timing=beyond_window) | effective hold | block | yes |
| S35 combo-3 (destination=popular_trusted, timing=beyond_window) | allow | block | yes |
| S35 combo-9 (delivery=inbound_request, entry=run_dialog, timing=beyond_window) | effective hold | block | yes |
| S35 timing=beyond_window (timing=beyond_window) | effective hold | block | no |
