# Hollow Knight Silksong

The game seems to always allocate runtime player data aligned to 4K boundaries.
Fields are at fixed offsets relative to this player data base pointer.

From player status base 0x00007f50cb624000

Pointer to player status base found at 

- `0x21c` u32 current hp
- `0x23c` u32 rosaries
- `0x240` u32 silk
- `0x908` u32 bone shards

From inventory base 0x00007f50cb7bb000

Pointer to inventory base found at 0x00007f50cb7b5018

0x00007f50cb7bb0ac - sting shard
0x00007f50cb7bb10c - longpin
0x00007f50cb7bb124 - flintslate
0x00007f50cb7bb13c - boomerang
0x00007f50cb7bb19c - straight pin
0x00007f50cb7bb1b4 - flea brew
0x00007f50cb7bb2a4 - cogwork wheel
0x00007f50cb7bb304 - plasmium phial
0x00007f50cb7bb37c - delver's drill
0x00007f50cb7bb3c4 - cogfly
0x00007f50cb7bb424 - silkshot
0x00007f50cb7bb454 - tacks
0x00007f50cb7bb46c - conchcutter
0x00007f50cb7bb484 - throwing ring
0x00007f50cb7bb4cc - rosary cannon



0x00007f50cb7dad50 - flea brew reserves
0x00007f50cb7dad68 - plasmium phial reserves

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
