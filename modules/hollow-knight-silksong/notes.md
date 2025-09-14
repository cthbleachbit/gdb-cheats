# Hollow Knight Silksong

The game seems to always allocate runtime player data aligned to 4K boundaries.
Fields are at fixed offsets relative to this player data base pointer.

## From player status base 0x00007f50cb624000

Pointer to player status base found at 

- `0x21c` u32 current hp
- `0x23c` u32 rosaries
- `0x240` u32 silk
- `0x908` u32 bone shards

## From inventory base 0x00007f50cb7bb000

000-01f: potentially a header
020-???: item entries? every item seems to take 24 bytes except for flea brew and plasmium phial

### Inside every 24B item entry:

000-007: Some pointer
008-00b: Fixed number 0x10001 / 65537
00c-00f: Item count as u32
010-014: Unknown number
015-018: 0xffffffff / -1

offset below is offset of item count u32

off + pointer at 0-7     + mapped item
0ac - 0x00007f32539a50f0 - sting shard
10c - 0x00007f32539b1f90 - longpin
124 - 0x00007f32539b1f30 - flintslate
13c - 0x00007f32539b1ed0 - curveclaw
19c - 0x00007f32539b1de0 - straight pin

2a4 - 0x00007f32539b19f0 - cogwork wheel
304 - 0x00007f325398c0c0 - plasmium phial
37c - 0x00007f32539b16f0 - delver's drill
3c4 - 0x00007f32539b7e40 - cogfly
424 - 0x00007f32539b7c80 - silkshot
454 - 0x00007f32539b8dc0 - tacks
46c - 0x00007f32539b1420 - conchcutter
484 - 0x00007f32539b13c0 - throwing ring
4cc - 0x00007f32539b7a80 - rosary cannon
55c - 0x00007f3232750720 - threefold pin
574 - 0x00007f3232750810 - pimpillo
58c - 0x00007f3232875b00 - curvesickle

### Exceptions - items with reserve

000-007: Some pointer A
008-00b: Fixed number 0x10001 / 65537
00c-00f: Item count as u32
010-014: Unknown number X
015-018: 0x10 <- Others have -1

1b4 - 0x00007f32539b1d80 - 7bea7f88 - flea brew

### Reserves section?

0x00007f50cb7dad50 - flea brew reserves
0x00007f50cb7dad68 - plasmium phial reserves

## From item base

0x00007f50cb855558 - pointer to item base = 0x00007f50cb85d000

0x00007f50cb85d050 - frayed rosary string +2
0x00007f50cb85d0b0 - craftmetal +5
0x00007f50cb85d0d0 - shard bundle +6
0x00007f50cb85d0f0 - rosary necklace +7
0x00007f50cb85d110 - rosary string +8
0x00007f50cb85d1d0 - memory locket +13
0x00007f50cb85d210 - beast shard +16
0x00007f50cb85d290 - heavy rosary necklace + 20
0x00007f50cb85d2f0 - silkeater +23
0x00007f50cb85d3f0 - hornet statuette +31
0x00007f50cb85d5b0 - seeker's soul
0x00007f50cb85d690 - pale rosary necklace
0x00007f50cb85d730 - hermit's soul
