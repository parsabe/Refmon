886 variants, identical event streams in every run (hash checked).

## Malicious variants

**All**

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 635 | 635 |
| block | 483 | 483 |
| effective hold | 142 | 142 |
| uncontained (allow + hold pauses nothing) | 10 | 10 |
| - allow | 10 | 10 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 0 | 0 |

**Variants the seed decides (324): the independent test**

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 324 | 324 |
| block | 223 | 223 |
| effective hold | 91 | 91 |
| uncontained (allow + hold pauses nothing) | 10 | 10 |
| - allow | 10 | 10 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 0 | 0 |

**Variants that are the same for every seed (311): a regression check, not fresh evidence**

| | v1.7 | v2.0 |
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

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 158 | 158 |
| allow | 132 | 137 |
| hold | 24 | 21 |
| block | 2 | 0 |
| block rate (the false block rate for neutral variants) | 1.3% | 0.0% |
| worse than the unmodified file | 5 | 0 |

**Benign, adds a contract violation (50)**

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 50 | 50 |
| allow | 17 | 17 |
| hold | 3 | 3 |
| block | 30 | 30 |
| block rate (the false block rate for neutral variants) | 60.0% | 60.0% |
| worse than the unmodified file | 0 | 0 |

**Benign, adds an effect (43)**

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 43 | 43 |
| allow | 0 | 0 |
| hold | 38 | 38 |
| block | 5 | 5 |
| block rate (the false block rate for neutral variants) | 11.6% | 11.6% |
| worse than the unmodified file | 0 | 0 |

**All benign variants**

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 251 | 251 |
| allow | 149 | 154 |
| hold | 65 | 62 |
| block | 37 | 35 |
| block rate (the false block rate for neutral variants) | 14.7% | 13.9% |
| worse than the unmodified file | 5 | 0 |

## Changes

**Malicious variants whose outcome changed, v1.7 to v2.0: 0**


| variant | v1.7 | v2.0 | seed decides |
|---|---|---|---|

**Benign variants whose outcome changed, v1.7 to v2.0: 5**

- block -> allow: 2
- hold -> allow: 3

| variant | v1.7 | v2.0 | seed decides |
|---|---|---|---|
| S24 combo-7 (delivery=inbound_request, timing=beyond_window) | hold | allow | yes |
| S24 timing=beyond_window (timing=beyond_window) | hold | allow | yes |
| S24 timing=minutes (timing=minutes) | hold | allow | yes |
| S37 combo-7 (delivery=inbound_request, timing=beyond_window) | block | allow | yes |
| S37 timing=beyond_window (timing=beyond_window) | block | allow | yes |
