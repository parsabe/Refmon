882 variants, identical event streams in every run (hash checked).

## Malicious variants

**All**

| | v1.4 | v1.5 |
|---|---:|---:|
| variants | 637 | 637 |
| block | 492 | 492 |
| effective hold | 138 | 139 |
| uncontained (allow + hold pauses nothing) | 7 | 6 |
| - allow | 6 | 5 |
| - hold pauses nothing | 1 | 1 |
| blocks that act on nothing | 0 | 0 |

**Variants the seed decides (326): the independent test**

| | v1.4 | v1.5 |
|---|---:|---:|
| variants | 326 | 326 |
| block | 232 | 232 |
| effective hold | 87 | 88 |
| uncontained (allow + hold pauses nothing) | 7 | 6 |
| - allow | 6 | 5 |
| - hold pauses nothing | 1 | 1 |
| blocks that act on nothing | 0 | 0 |

**Variants that are the same for every seed (311): a regression check, not fresh evidence**

| | v1.4 | v1.5 |
|---|---:|---:|
| variants | 311 | 311 |
| block | 260 | 260 |
| effective hold | 51 | 51 |
| uncontained (allow + hold pauses nothing) | 0 | 0 |
| - allow | 0 | 0 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 0 | 0 |

## Benign variants

**Benign, neutral (158)**

| | v1.4 | v1.5 |
|---|---:|---:|
| variants | 158 | 158 |
| allow | 136 | 136 |
| hold | 21 | 21 |
| block | 1 | 1 |
| block rate (the false block rate for neutral variants) | 0.6% | 0.6% |
| worse than the unmodified file | 4 | 4 |

**Benign, adds a contract violation (52)**

| | v1.4 | v1.5 |
|---|---:|---:|
| variants | 52 | 52 |
| allow | 14 | 14 |
| hold | 4 | 4 |
| block | 34 | 34 |
| block rate (the false block rate for neutral variants) | 65.4% | 65.4% |
| worse than the unmodified file | 0 | 0 |

**Benign, adds an effect (35)**

| | v1.4 | v1.5 |
|---|---:|---:|
| variants | 35 | 35 |
| allow | 0 | 0 |
| hold | 32 | 32 |
| block | 3 | 3 |
| block rate (the false block rate for neutral variants) | 8.6% | 8.6% |
| worse than the unmodified file | 0 | 0 |

**All benign variants**

| | v1.4 | v1.5 |
|---|---:|---:|
| variants | 245 | 245 |
| allow | 150 | 150 |
| hold | 57 | 57 |
| block | 38 | 38 |
| block rate (the false block rate for neutral variants) | 15.5% | 15.5% |
| worse than the unmodified file | 4 | 4 |

## Changes

**Malicious variants whose outcome changed, v1.4 to v1.5: 1**

- allow -> effective hold: 1

| variant | v1.4 | v1.5 | seed decides |
|---|---|---|---|
| S18 combo-1 (destination=popular_trusted, timing=beyond_window) | allow | effective hold | yes |

**Benign variants whose outcome changed, v1.4 to v1.5: 0**


| variant | v1.4 | v1.5 | seed decides |
|---|---|---|---|
