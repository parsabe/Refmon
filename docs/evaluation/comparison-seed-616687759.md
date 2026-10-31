878 variants, identical event streams in every run (hash checked).

## Malicious variants

**All**

| | v1.6 | v1.7 |
|---|---:|---:|
| variants | 634 | 634 |
| block | 480 | 480 |
| effective hold | 143 | 143 |
| uncontained (allow + hold pauses nothing) | 11 | 11 |
| - allow | 8 | 8 |
| - hold pauses nothing | 3 | 3 |
| blocks that act on nothing | 0 | 0 |

**Variants the seed decides (323): the independent test**

| | v1.6 | v1.7 |
|---|---:|---:|
| variants | 323 | 323 |
| block | 220 | 220 |
| effective hold | 92 | 92 |
| uncontained (allow + hold pauses nothing) | 11 | 11 |
| - allow | 8 | 8 |
| - hold pauses nothing | 3 | 3 |
| blocks that act on nothing | 0 | 0 |

**Variants that are the same for every seed (311): a regression check, not fresh evidence**

| | v1.6 | v1.7 |
|---|---:|---:|
| variants | 311 | 311 |
| block | 260 | 260 |
| effective hold | 51 | 51 |
| uncontained (allow + hold pauses nothing) | 0 | 0 |
| - allow | 0 | 0 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 0 | 0 |

## Benign variants

**Benign, neutral (154)**

| | v1.6 | v1.7 |
|---|---:|---:|
| variants | 154 | 154 |
| allow | 128 | 128 |
| hold | 23 | 23 |
| block | 3 | 3 |
| block rate (the false block rate for neutral variants) | 1.9% | 1.9% |
| worse than the unmodified file | 6 | 6 |

**Benign, adds a contract violation (51)**

| | v1.6 | v1.7 |
|---|---:|---:|
| variants | 51 | 51 |
| allow | 18 | 18 |
| hold | 4 | 4 |
| block | 29 | 29 |
| block rate (the false block rate for neutral variants) | 56.9% | 56.9% |
| worse than the unmodified file | 0 | 0 |

**Benign, adds an effect (39)**

| | v1.6 | v1.7 |
|---|---:|---:|
| variants | 39 | 39 |
| allow | 0 | 0 |
| hold | 33 | 33 |
| block | 6 | 6 |
| block rate (the false block rate for neutral variants) | 15.4% | 15.4% |
| worse than the unmodified file | 0 | 0 |

**All benign variants**

| | v1.6 | v1.7 |
|---|---:|---:|
| variants | 244 | 244 |
| allow | 146 | 146 |
| hold | 60 | 60 |
| block | 38 | 38 |
| block rate (the false block rate for neutral variants) | 15.6% | 15.6% |
| worse than the unmodified file | 6 | 6 |

## Changes

**Malicious variants whose outcome changed, v1.6 to v1.7: 0**


| variant | v1.6 | v1.7 | seed decides |
|---|---|---|---|

**Benign variants whose outcome changed, v1.6 to v1.7: 0**


| variant | v1.6 | v1.7 | seed decides |
|---|---|---|---|
