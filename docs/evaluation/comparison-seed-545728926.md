888 variants, identical event streams in every run (hash checked).

## Malicious variants

**All**

| | v1.5 | v1.6 |
|---|---:|---:|
| variants | 636 | 636 |
| block | 485 | 485 |
| effective hold | 138 | 139 |
| uncontained (allow + hold pauses nothing) | 13 | 12 |
| - allow | 11 | 11 |
| - hold pauses nothing | 2 | 1 |
| blocks that act on nothing | 0 | 0 |

**Variants the seed decides (325): the independent test**

| | v1.5 | v1.6 |
|---|---:|---:|
| variants | 325 | 325 |
| block | 225 | 225 |
| effective hold | 87 | 88 |
| uncontained (allow + hold pauses nothing) | 13 | 12 |
| - allow | 11 | 11 |
| - hold pauses nothing | 2 | 1 |
| blocks that act on nothing | 0 | 0 |

**Variants that are the same for every seed (311): a regression check, not fresh evidence**

| | v1.5 | v1.6 |
|---|---:|---:|
| variants | 311 | 311 |
| block | 260 | 260 |
| effective hold | 51 | 51 |
| uncontained (allow + hold pauses nothing) | 0 | 0 |
| - allow | 0 | 0 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 0 | 0 |

## Benign variants

**Benign, neutral (161)**

| | v1.5 | v1.6 |
|---|---:|---:|
| variants | 161 | 161 |
| allow | 136 | 136 |
| hold | 24 | 24 |
| block | 1 | 1 |
| block rate (the false block rate for neutral variants) | 0.6% | 0.6% |
| worse than the unmodified file | 3 | 3 |

**Benign, adds a contract violation (55)**

| | v1.5 | v1.6 |
|---|---:|---:|
| variants | 55 | 55 |
| allow | 20 | 20 |
| hold | 5 | 5 |
| block | 30 | 30 |
| block rate (the false block rate for neutral variants) | 54.5% | 54.5% |
| worse than the unmodified file | 0 | 0 |

**Benign, adds an effect (36)**

| | v1.5 | v1.6 |
|---|---:|---:|
| variants | 36 | 36 |
| allow | 0 | 0 |
| hold | 32 | 32 |
| block | 4 | 4 |
| block rate (the false block rate for neutral variants) | 11.1% | 11.1% |
| worse than the unmodified file | 0 | 0 |

**All benign variants**

| | v1.5 | v1.6 |
|---|---:|---:|
| variants | 252 | 252 |
| allow | 156 | 156 |
| hold | 61 | 61 |
| block | 35 | 35 |
| block rate (the false block rate for neutral variants) | 13.9% | 13.9% |
| worse than the unmodified file | 3 | 3 |

## Changes

**Malicious variants whose outcome changed, v1.5 to v1.6: 1**

- hold pauses nothing -> effective hold: 1

| variant | v1.5 | v1.6 | seed decides |
|---|---|---|---|
| S12 combo-1 (entry=file_manager, timing=minutes) | hold pauses nothing | effective hold | yes |

**Benign variants whose outcome changed, v1.5 to v1.6: 0**


| variant | v1.5 | v1.6 | seed decides |
|---|---|---|---|
