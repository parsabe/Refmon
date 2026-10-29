879 variants, identical event streams in every run (hash checked).

## Malicious variants

**All**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 633 | 633 | 633 | 633 |
| block | 425 | 467 | 467 | 486 |
| effective hold | 121 | 157 | 157 | 139 |
| uncontained (allow + hold pauses nothing) | 87 | 9 | 9 | 8 |
| - allow | 18 | 9 | 9 | 8 |
| - hold pauses nothing | 69 | 0 | 0 | 0 |
| blocks that act on nothing | 11 | 9 | 0 | 0 |

**Variants the seed decides (322): the independent test**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 322 | 322 | 322 | 322 |
| block | 182 | 207 | 207 | 226 |
| effective hold | 87 | 106 | 106 | 88 |
| uncontained (allow + hold pauses nothing) | 53 | 9 | 9 | 8 |
| - allow | 16 | 9 | 9 | 8 |
| - hold pauses nothing | 37 | 0 | 0 | 0 |
| blocks that act on nothing | 6 | 4 | 0 | 0 |

**Variants that are the same for every seed (311): a regression check, not fresh evidence**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 311 | 311 | 311 | 311 |
| block | 243 | 260 | 260 | 260 |
| effective hold | 34 | 51 | 51 | 51 |
| uncontained (allow + hold pauses nothing) | 34 | 0 | 0 | 0 |
| - allow | 2 | 0 | 0 | 0 |
| - hold pauses nothing | 32 | 0 | 0 | 0 |
| blocks that act on nothing | 5 | 5 | 0 | 0 |

## Benign variants

**Benign, neutral (151)**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 151 | 151 | 151 | 151 |
| allow | 126 | 126 | 126 | 125 |
| hold | 22 | 22 | 22 | 23 |
| block | 3 | 3 | 3 | 3 |
| block rate (the false block rate for neutral variants) | 2.0% | 2.0% | 2.0% | 2.0% |
| worse than the unmodified file | 5 | 5 | 5 | 5 |

**Benign, adds a contract violation (55)**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 55 | 55 | 55 | 55 |
| allow | 17 | 17 | 17 | 17 |
| hold | 8 | 6 | 6 | 4 |
| block | 30 | 32 | 32 | 34 |
| block rate (the false block rate for neutral variants) | 54.5% | 58.2% | 58.2% | 61.8% |
| worse than the unmodified file | 0 | 0 | 0 | 0 |

**Benign, adds an effect (40)**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 40 | 40 | 40 | 40 |
| allow | 1 | 1 | 1 | 0 |
| hold | 34 | 34 | 34 | 35 |
| block | 5 | 5 | 5 | 5 |
| block rate (the false block rate for neutral variants) | 12.5% | 12.5% | 12.5% | 12.5% |
| worse than the unmodified file | 0 | 0 | 0 | 0 |

**All benign variants**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 246 | 246 | 246 | 246 |
| allow | 144 | 144 | 144 | 142 |
| hold | 64 | 62 | 62 | 62 |
| block | 38 | 40 | 40 | 42 |
| block rate (the false block rate for neutral variants) | 15.4% | 16.3% | 16.3% | 17.1% |
| worse than the unmodified file | 5 | 5 | 5 | 5 |

## Changes

**Malicious variants whose outcome changed, v1.0 to v1.1: 119**

- allow -> block: 3
- allow -> effective hold: 6
- block -> effective hold: 2
- effective hold -> block: 39
- hold pauses nothing -> block: 2
- hold pauses nothing -> effective hold: 67

| variant | v1.0 | v1.1 | seed decides |
|---|---|---|---|
| S01 combo-6 (delivery=typed, destination=internal_network, entry=script_host) | hold pauses nothing | effective hold | yes |
| S01 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S02 combo-11 (delivery=typed, timing=minutes) | hold pauses nothing | effective hold | yes |
| S02 combo-2 (delivery=typed, obfuscation=high_entropy, timing=minutes) | hold pauses nothing | effective hold | yes |
| S02 combo-4 (delivery=dragged, timing=minutes) | block | effective hold | yes |
| S02 combo-8 (delivery=typed, destination=popular_trusted, lineage=2, obfuscation=stripped) | hold pauses nothing | effective hold | yes |
| S02 combo-9 (delivery=typed, lineage=3, timing=minutes) | hold pauses nothing | effective hold | yes |
| S02 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S02 entry=file_manager (entry=file_manager) | effective hold | block | no |
| S02 entry=run_dialog (entry=run_dialog) | effective hold | block | no |
| S02 entry=scheduled_task (entry=scheduled_task) | effective hold | block | no |
| S02 entry=script_host (entry=script_host) | effective hold | block | no |
| S02 timing=minutes (timing=minutes) | block | effective hold | yes |
| S03 combo-10 (delivery=typed, lineage=3, obfuscation=stripped) | hold pauses nothing | effective hold | yes |
| S03 combo-11 (lineage=1, obfuscation=high_entropy, timing=minutes) | effective hold | block | yes |
| S03 combo-2 (destination=internal_network, lineage=3, obfuscation=padded, timing=minutes) | effective hold | block | yes |
| S03 combo-3 (destination=internal_network, entry=terminal, lineage=2, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S03 combo-7 (delivery=typed, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S03 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S04 combo-1 (delivery=inbound_request, entry=file_manager, lineage=3) | effective hold | block | yes |
| S04 combo-10 (destination=popular_trusted, entry=run_dialog, obfuscation=high_entropy, timing=minutes) | effective hold | block | yes |
| S04 combo-11 (delivery=typed, destination=popular_trusted) | hold pauses nothing | effective hold | yes |
| S04 combo-3 (delivery=opened, timing=minutes) | effective hold | block | yes |
| S04 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S04 entry=file_manager (entry=file_manager) | effective hold | block | no |
| S04 entry=run_dialog (entry=run_dialog) | effective hold | block | no |
| S04 entry=scheduled_task (entry=scheduled_task) | effective hold | block | no |
| S04 entry=script_host (entry=script_host) | effective hold | block | no |
| S05 baseline (unmodified) | hold pauses nothing | effective hold | no |
| S05 combo-1 (destination=internal_network, lineage=3, obfuscation=stripped) | hold pauses nothing | effective hold | yes |
| S05 combo-10 (lineage=4, obfuscation=padded) | hold pauses nothing | effective hold | yes |
| S05 combo-11 (delivery=dragged, lineage=1, obfuscation=padded, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S05 combo-12 (destination=internal_network, entry=script_host, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S05 combo-2 (delivery=typed, destination=internal_network, obfuscation=high_entropy) | hold pauses nothing | effective hold | yes |
| S05 combo-4 (delivery=dragged, destination=internal_network, lineage=2, obfuscation=padded) | hold pauses nothing | effective hold | yes |
| S05 combo-5 (lineage=1, obfuscation=high_entropy, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S05 combo-7 (delivery=opened, destination=popular_trusted) | hold pauses nothing | effective hold | yes |
| S05 combo-8 (destination=popular_trusted, lineage=2) | hold pauses nothing | effective hold | yes |
| S05 combo-9 (destination=popular_trusted, lineage=4, obfuscation=high_entropy, timing=minutes) | hold pauses nothing | effective hold | yes |
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
| S05 obfuscation=high_entropy (obfuscation=high_entropy) | hold pauses nothing | effective hold | yes |
| S05 obfuscation=padded (obfuscation=padded) | hold pauses nothing | effective hold | yes |
| S05 obfuscation=stripped (obfuscation=stripped) | hold pauses nothing | effective hold | no |
| S05 timing=beyond_window (timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S05 timing=minutes (timing=minutes) | hold pauses nothing | effective hold | yes |
| S06 combo-2 (destination=internal_network, entry=scheduled_task) | effective hold | block | yes |
| S06 combo-6 (delivery=typed, destination=popular_trusted, entry=terminal) | hold pauses nothing | effective hold | yes |
| S06 combo-7 (delivery=inbound_request, destination=popular_trusted, entry=scheduled_task, lineage=4) | effective hold | block | yes |
| S06 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S06 entry=file_manager (entry=file_manager) | effective hold | block | no |
| S06 entry=run_dialog (entry=run_dialog) | effective hold | block | no |
| S06 entry=scheduled_task (entry=scheduled_task) | effective hold | block | no |
| S06 entry=script_host (entry=script_host) | effective hold | block | no |
| S07 combo-1 (delivery=inbound_request, destination=popular_trusted, lineage=4) | allow | block | yes |
| S07 combo-10 (delivery=typed, lineage=1) | hold pauses nothing | effective hold | yes |
| S07 combo-11 (entry=scheduled_task, obfuscation=stripped) | effective hold | block | yes |
| S07 combo-12 (destination=popular_trusted, entry=terminal, lineage=1, obfuscation=stripped) | allow | block | yes |
| S07 combo-3 (delivery=dragged, entry=run_dialog, lineage=3) | effective hold | block | yes |
| S07 combo-5 (destination=popular_trusted, entry=terminal, timing=minutes) | allow | effective hold | yes |
| S07 delivery=typed (delivery=typed) | hold pauses nothing | effective hold | no |
| S07 destination=popular_trusted (destination=popular_trusted) | allow | block | no |
| S07 entry=file_manager (entry=file_manager) | effective hold | block | no |
| S07 entry=run_dialog (entry=run_dialog) | effective hold | block | no |
| S07 entry=scheduled_task (entry=scheduled_task) | effective hold | block | no |
| S07 entry=script_host (entry=script_host) | effective hold | block | no |
| S12 entry=file_manager (entry=file_manager) | hold pauses nothing | effective hold | no |
| S12 entry=run_dialog (entry=run_dialog) | hold pauses nothing | effective hold | no |
| S13 combo-11 (destination=internal_network, entry=file_manager, timing=minutes) | hold pauses nothing | effective hold | yes |
| S13 combo-12 (destination=internal_network, entry=run_dialog, obfuscation=high_entropy) | hold pauses nothing | effective hold | yes |
| S13 combo-5 (entry=file_manager, obfuscation=high_entropy, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S13 combo-6 (entry=web_worker, obfuscation=stripped, timing=beyond_window) | effective hold | block | yes |
| S13 combo-9 (destination=internal_network, timing=minutes) | effective hold | block | yes |
| S13 entry=file_manager (entry=file_manager) | hold pauses nothing | effective hold | no |
| S13 entry=run_dialog (entry=run_dialog) | hold pauses nothing | effective hold | no |
| S13 timing=beyond_window (timing=beyond_window) | effective hold | block | yes |
| S18 combo-10 (destination=popular_trusted, timing=minutes) | allow | effective hold | yes |
| S18 combo-8 (destination=popular_trusted, lineage=2) | allow | effective hold | yes |
| S18 destination=popular_trusted (destination=popular_trusted) | allow | effective hold | no |
| S21 combo-3 (entry=file_manager, timing=minutes) | hold pauses nothing | effective hold | yes |
| S21 combo-5 (entry=web_worker, timing=beyond_window) | effective hold | block | yes |
| S21 entry=file_manager (entry=file_manager) | hold pauses nothing | effective hold | no |
| S21 entry=run_dialog (entry=run_dialog) | hold pauses nothing | effective hold | no |
| S25 combo-12 (entry=run_dialog, obfuscation=padded) | hold pauses nothing | effective hold | yes |
| S25 combo-2 (entry=run_dialog, lineage=2, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S25 combo-4 (destination=internal_network, entry=file_manager, obfuscation=high_entropy, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S25 combo-5 (destination=popular_trusted, entry=scheduled_task, lineage=3) | allow | effective hold | yes |
| S25 combo-7 (destination=popular_trusted, entry=scheduled_task) | allow | effective hold | yes |
| S25 combo-8 (entry=terminal, lineage=3, timing=minutes) | hold pauses nothing | block | yes |
| S25 combo-9 (destination=popular_trusted, obfuscation=stripped, timing=beyond_window) | effective hold | block | yes |
| S25 entry=file_manager (entry=file_manager) | hold pauses nothing | effective hold | no |
| S25 entry=run_dialog (entry=run_dialog) | hold pauses nothing | effective hold | no |
| S26b combo-5 (destination=popular_trusted, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S31 combo-7 (lineage=3, obfuscation=stripped, timing=minutes) | effective hold | block | yes |
| S31 combo-8 (destination=internal_network, entry=file_manager, lineage=4) | hold pauses nothing | effective hold | yes |
| S31 entry=file_manager (entry=file_manager) | hold pauses nothing | effective hold | no |
| S31 entry=run_dialog (entry=run_dialog) | hold pauses nothing | effective hold | no |
| S32 combo-12 (destination=internal_network, timing=minutes) | effective hold | block | yes |
| S32 combo-3 (destination=internal_network, entry=run_dialog, obfuscation=stripped, timing=minutes) | effective hold | block | yes |
| S33 combo-1 (entry=run_dialog, lineage=3, timing=beyond_window) | hold pauses nothing | effective hold | yes |
| S33 combo-10 (entry=terminal, timing=minutes) | effective hold | block | yes |
| S33 combo-2 (obfuscation=stripped, timing=minutes) | effective hold | block | yes |
| S34 combo-5 (delivery=inbound_request, timing=beyond_window) | effective hold | block | yes |
| S34 combo-8 (entry=run_dialog, lineage=4, timing=beyond_window) | effective hold | block | yes |
| S34 timing=beyond_window (timing=beyond_window) | effective hold | block | yes |
| S35 combo-5 (entry=terminal, timing=minutes) | effective hold | block | yes |
| S35 combo-7 (destination=internal_network, timing=minutes) | hold pauses nothing | block | yes |

**Malicious variants whose outcome changed, v1.1 to v1.2: 0**


| variant | v1.1 | v1.2 | seed decides |
|---|---|---|---|

**Malicious variants whose outcome changed, v1.2 to v1.3: 20**

- allow -> effective hold: 1
- effective hold -> block: 19

| variant | v1.2 | v1.3 | seed decides |
|---|---|---|---|
| S01 combo-5 (delivery=inbound_request, destination=popular_trusted, obfuscation=padded, timing=minutes) | effective hold | block | yes |
| S01 timing=minutes (timing=minutes) | effective hold | block | yes |
| S02 combo-3 (lineage=2, obfuscation=padded, timing=minutes) | effective hold | block | yes |
| S02 combo-4 (delivery=dragged, timing=minutes) | effective hold | block | yes |
| S02 combo-6 (delivery=dragged, destination=internal_network, timing=minutes) | effective hold | block | yes |
| S02 combo-7 (lineage=1, timing=beyond_window) | effective hold | block | yes |
| S02 timing=minutes (timing=minutes) | effective hold | block | yes |
| S03 timing=minutes (timing=minutes) | effective hold | block | yes |
| S04 combo-12 (delivery=inbound_request, entry=terminal, obfuscation=high_entropy, timing=beyond_window) | effective hold | block | yes |
| S04 timing=minutes (timing=minutes) | effective hold | block | yes |
| S06 combo-4 (delivery=dragged, destination=internal_network, timing=minutes) | effective hold | block | yes |
| S06 combo-8 (destination=popular_trusted, lineage=3, timing=beyond_window) | effective hold | block | yes |
| S06 timing=minutes (timing=minutes) | effective hold | block | yes |
| S07 combo-5 (destination=popular_trusted, entry=terminal, timing=minutes) | effective hold | block | yes |
| S07 timing=minutes (timing=minutes) | effective hold | block | yes |
| S26b combo-5 (destination=popular_trusted, timing=beyond_window) | effective hold | block | yes |
| S27 timing=beyond_window (timing=beyond_window) | allow | effective hold | yes |
| S32 timing=beyond_window (timing=beyond_window) | effective hold | block | yes |
| S33 timing=beyond_window (timing=beyond_window) | effective hold | block | yes |
| S35 timing=beyond_window (timing=beyond_window) | effective hold | block | yes |

**Benign variants whose outcome changed, v1.0 to v1.1: 2**

- hold -> block: 2

| variant | v1.0 | v1.1 | seed decides |
|---|---|---|---|
| S11 combo-7 (delivery=inbound_request, entry=scheduled_task, lineage=2, obfuscation=padded) | hold | block | yes |
| S11 combo-8 (entry=scheduled_task, obfuscation=padded) | hold | block | yes |

**Benign variants whose outcome changed, v1.1 to v1.2: 0**


| variant | v1.1 | v1.2 | seed decides |
|---|---|---|---|

**Benign variants whose outcome changed, v1.2 to v1.3: 4**

- allow -> hold: 2
- hold -> block: 2

| variant | v1.2 | v1.3 | seed decides |
|---|---|---|---|
| S30 combo-6 (entry=scheduled_task, obfuscation=high_entropy, timing=beyond_window) | allow | hold | yes |
| S36 combo-10 (entry=web_worker, timing=minutes) | hold | block | yes |
| S38 combo-12 (entry=terminal, obfuscation=padded, timing=beyond_window) | hold | block | yes |
| S49 combo-4 (lineage=3, timing=minutes) | allow | hold | yes |
