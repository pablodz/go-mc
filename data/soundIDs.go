package data

//go:generate bash -c "go run gen_soundIDs.go > soundIDs.go"

// This file is automatically generated by gen_soundIDs.go. DO NOT EDIT.

// SoundID represents a sound ID used in the minecraft protocol.
type SoundID int32

// SoundNames - map of ids to names for sounds.
var SoundNames map[SoundID]string = map[SoundID]string{
    0: "ambient.cave",
    1: "ambient.basalt_deltas.additions",
    2: "ambient.basalt_deltas.loop",
    3: "ambient.basalt_deltas.mood",
    4: "ambient.crimson_forest.additions",
    5: "ambient.crimson_forest.loop",
    6: "ambient.crimson_forest.mood",
    7: "ambient.nether_wastes.additions",
    8: "ambient.nether_wastes.loop",
    9: "ambient.nether_wastes.mood",
    10: "ambient.soul_sand_valley.additions",
    11: "ambient.soul_sand_valley.loop",
    12: "ambient.soul_sand_valley.mood",
    13: "ambient.warped_forest.additions",
    14: "ambient.warped_forest.loop",
    15: "ambient.warped_forest.mood",
    16: "ambient.underwater.enter",
    17: "ambient.underwater.exit",
    18: "ambient.underwater.loop",
    19: "ambient.underwater.loop.additions",
    20: "ambient.underwater.loop.additions.rare",
    21: "ambient.underwater.loop.additions.ultra_rare",
    22: "block.ancient_debris.break",
    23: "block.ancient_debris.step",
    24: "block.ancient_debris.place",
    25: "block.ancient_debris.hit",
    26: "block.ancient_debris.fall",
    27: "block.anvil.break",
    28: "block.anvil.destroy",
    29: "block.anvil.fall",
    30: "block.anvil.hit",
    31: "block.anvil.land",
    32: "block.anvil.place",
    33: "block.anvil.step",
    34: "block.anvil.use",
    35: "item.armor.equip_chain",
    36: "item.armor.equip_diamond",
    37: "item.armor.equip_elytra",
    38: "item.armor.equip_generic",
    39: "item.armor.equip_gold",
    40: "item.armor.equip_iron",
    41: "item.armor.equip_leather",
    42: "item.armor.equip_netherite",
    43: "item.armor.equip_turtle",
    44: "entity.armor_stand.break",
    45: "entity.armor_stand.fall",
    46: "entity.armor_stand.hit",
    47: "entity.armor_stand.place",
    48: "entity.arrow.hit",
    49: "entity.arrow.hit_player",
    50: "entity.arrow.shoot",
    51: "item.axe.strip",
    52: "block.bamboo.break",
    53: "block.bamboo.fall",
    54: "block.bamboo.hit",
    55: "block.bamboo.place",
    56: "block.bamboo.step",
    57: "block.bamboo_sapling.break",
    58: "block.bamboo_sapling.hit",
    59: "block.bamboo_sapling.place",
    60: "block.barrel.close",
    61: "block.barrel.open",
    62: "block.basalt.break",
    63: "block.basalt.step",
    64: "block.basalt.place",
    65: "block.basalt.hit",
    66: "block.basalt.fall",
    67: "entity.bat.ambient",
    68: "entity.bat.death",
    69: "entity.bat.hurt",
    70: "entity.bat.loop",
    71: "entity.bat.takeoff",
    72: "block.beacon.activate",
    73: "block.beacon.ambient",
    74: "block.beacon.deactivate",
    75: "block.beacon.power_select",
    76: "entity.bee.death",
    77: "entity.bee.hurt",
    78: "entity.bee.loop_aggressive",
    79: "entity.bee.loop",
    80: "entity.bee.sting",
    81: "entity.bee.pollinate",
    82: "block.beehive.drip",
    83: "block.beehive.enter",
    84: "block.beehive.exit",
    85: "block.beehive.shear",
    86: "block.beehive.work",
    87: "block.bell.use",
    88: "block.bell.resonate",
    89: "entity.blaze.ambient",
    90: "entity.blaze.burn",
    91: "entity.blaze.death",
    92: "entity.blaze.hurt",
    93: "entity.blaze.shoot",
    94: "entity.boat.paddle_land",
    95: "entity.boat.paddle_water",
    96: "block.bone_block.break",
    97: "block.bone_block.fall",
    98: "block.bone_block.hit",
    99: "block.bone_block.place",
    100: "block.bone_block.step",
    101: "item.book.page_turn",
    102: "item.book.put",
    103: "block.blastfurnace.fire_crackle",
    104: "item.bottle.empty",
    105: "item.bottle.fill",
    106: "item.bottle.fill_dragonbreath",
    107: "block.brewing_stand.brew",
    108: "block.bubble_column.bubble_pop",
    109: "block.bubble_column.upwards_ambient",
    110: "block.bubble_column.upwards_inside",
    111: "block.bubble_column.whirlpool_ambient",
    112: "block.bubble_column.whirlpool_inside",
    113: "item.bucket.empty",
    114: "item.bucket.empty_fish",
    115: "item.bucket.empty_lava",
    116: "item.bucket.fill",
    117: "item.bucket.fill_fish",
    118: "item.bucket.fill_lava",
    119: "block.campfire.crackle",
    120: "entity.cat.ambient",
    121: "entity.cat.stray_ambient",
    122: "entity.cat.death",
    123: "entity.cat.eat",
    124: "entity.cat.hiss",
    125: "entity.cat.beg_for_food",
    126: "entity.cat.hurt",
    127: "entity.cat.purr",
    128: "entity.cat.purreow",
    129: "block.chain.break",
    130: "block.chain.fall",
    131: "block.chain.hit",
    132: "block.chain.place",
    133: "block.chain.step",
    134: "block.chest.close",
    135: "block.chest.locked",
    136: "block.chest.open",
    137: "entity.chicken.ambient",
    138: "entity.chicken.death",
    139: "entity.chicken.egg",
    140: "entity.chicken.hurt",
    141: "entity.chicken.step",
    142: "block.chorus_flower.death",
    143: "block.chorus_flower.grow",
    144: "item.chorus_fruit.teleport",
    145: "entity.cod.ambient",
    146: "entity.cod.death",
    147: "entity.cod.flop",
    148: "entity.cod.hurt",
    149: "block.comparator.click",
    150: "block.composter.empty",
    151: "block.composter.fill",
    152: "block.composter.fill_success",
    153: "block.composter.ready",
    154: "block.conduit.activate",
    155: "block.conduit.ambient",
    156: "block.conduit.ambient.short",
    157: "block.conduit.attack.target",
    158: "block.conduit.deactivate",
    159: "block.coral_block.break",
    160: "block.coral_block.fall",
    161: "block.coral_block.hit",
    162: "block.coral_block.place",
    163: "block.coral_block.step",
    164: "entity.cow.ambient",
    165: "entity.cow.death",
    166: "entity.cow.hurt",
    167: "entity.cow.milk",
    168: "entity.cow.step",
    169: "entity.creeper.death",
    170: "entity.creeper.hurt",
    171: "entity.creeper.primed",
    172: "block.crop.break",
    173: "item.crop.plant",
    174: "item.crossbow.hit",
    175: "item.crossbow.loading_end",
    176: "item.crossbow.loading_middle",
    177: "item.crossbow.loading_start",
    178: "item.crossbow.quick_charge_1",
    179: "item.crossbow.quick_charge_2",
    180: "item.crossbow.quick_charge_3",
    181: "item.crossbow.shoot",
    182: "block.dispenser.dispense",
    183: "block.dispenser.fail",
    184: "block.dispenser.launch",
    185: "entity.dolphin.ambient",
    186: "entity.dolphin.ambient_water",
    187: "entity.dolphin.attack",
    188: "entity.dolphin.death",
    189: "entity.dolphin.eat",
    190: "entity.dolphin.hurt",
    191: "entity.dolphin.jump",
    192: "entity.dolphin.play",
    193: "entity.dolphin.splash",
    194: "entity.dolphin.swim",
    195: "entity.donkey.ambient",
    196: "entity.donkey.angry",
    197: "entity.donkey.chest",
    198: "entity.donkey.death",
    199: "entity.donkey.eat",
    200: "entity.donkey.hurt",
    201: "entity.drowned.ambient",
    202: "entity.drowned.ambient_water",
    203: "entity.drowned.death",
    204: "entity.drowned.death_water",
    205: "entity.drowned.hurt",
    206: "entity.drowned.hurt_water",
    207: "entity.drowned.shoot",
    208: "entity.drowned.step",
    209: "entity.drowned.swim",
    210: "entity.egg.throw",
    211: "entity.elder_guardian.ambient",
    212: "entity.elder_guardian.ambient_land",
    213: "entity.elder_guardian.curse",
    214: "entity.elder_guardian.death",
    215: "entity.elder_guardian.death_land",
    216: "entity.elder_guardian.flop",
    217: "entity.elder_guardian.hurt",
    218: "entity.elder_guardian.hurt_land",
    219: "item.elytra.flying",
    220: "block.enchantment_table.use",
    221: "block.ender_chest.close",
    222: "block.ender_chest.open",
    223: "entity.ender_dragon.ambient",
    224: "entity.ender_dragon.death",
    225: "entity.dragon_fireball.explode",
    226: "entity.ender_dragon.flap",
    227: "entity.ender_dragon.growl",
    228: "entity.ender_dragon.hurt",
    229: "entity.ender_dragon.shoot",
    230: "entity.ender_eye.death",
    231: "entity.ender_eye.launch",
    232: "entity.enderman.ambient",
    233: "entity.enderman.death",
    234: "entity.enderman.hurt",
    235: "entity.enderman.scream",
    236: "entity.enderman.stare",
    237: "entity.enderman.teleport",
    238: "entity.endermite.ambient",
    239: "entity.endermite.death",
    240: "entity.endermite.hurt",
    241: "entity.endermite.step",
    242: "entity.ender_pearl.throw",
    243: "block.end_gateway.spawn",
    244: "block.end_portal_frame.fill",
    245: "block.end_portal.spawn",
    246: "entity.evoker.ambient",
    247: "entity.evoker.cast_spell",
    248: "entity.evoker.celebrate",
    249: "entity.evoker.death",
    250: "entity.evoker_fangs.attack",
    251: "entity.evoker.hurt",
    252: "entity.evoker.prepare_attack",
    253: "entity.evoker.prepare_summon",
    254: "entity.evoker.prepare_wololo",
    255: "entity.experience_bottle.throw",
    256: "entity.experience_orb.pickup",
    257: "block.fence_gate.close",
    258: "block.fence_gate.open",
    259: "item.firecharge.use",
    260: "entity.firework_rocket.blast",
    261: "entity.firework_rocket.blast_far",
    262: "entity.firework_rocket.large_blast",
    263: "entity.firework_rocket.large_blast_far",
    264: "entity.firework_rocket.launch",
    265: "entity.firework_rocket.shoot",
    266: "entity.firework_rocket.twinkle",
    267: "entity.firework_rocket.twinkle_far",
    268: "block.fire.ambient",
    269: "block.fire.extinguish",
    270: "entity.fish.swim",
    271: "entity.fishing_bobber.retrieve",
    272: "entity.fishing_bobber.splash",
    273: "entity.fishing_bobber.throw",
    274: "item.flintandsteel.use",
    275: "entity.fox.aggro",
    276: "entity.fox.ambient",
    277: "entity.fox.bite",
    278: "entity.fox.death",
    279: "entity.fox.eat",
    280: "entity.fox.hurt",
    281: "entity.fox.screech",
    282: "entity.fox.sleep",
    283: "entity.fox.sniff",
    284: "entity.fox.spit",
    285: "entity.fox.teleport",
    286: "block.roots.break",
    287: "block.roots.step",
    288: "block.roots.place",
    289: "block.roots.hit",
    290: "block.roots.fall",
    291: "block.furnace.fire_crackle",
    292: "entity.generic.big_fall",
    293: "entity.generic.burn",
    294: "entity.generic.death",
    295: "entity.generic.drink",
    296: "entity.generic.eat",
    297: "entity.generic.explode",
    298: "entity.generic.extinguish_fire",
    299: "entity.generic.hurt",
    300: "entity.generic.small_fall",
    301: "entity.generic.splash",
    302: "entity.generic.swim",
    303: "entity.ghast.ambient",
    304: "entity.ghast.death",
    305: "entity.ghast.hurt",
    306: "entity.ghast.scream",
    307: "entity.ghast.shoot",
    308: "entity.ghast.warn",
    309: "block.gilded_blackstone.break",
    310: "block.gilded_blackstone.fall",
    311: "block.gilded_blackstone.hit",
    312: "block.gilded_blackstone.place",
    313: "block.gilded_blackstone.step",
    314: "block.glass.break",
    315: "block.glass.fall",
    316: "block.glass.hit",
    317: "block.glass.place",
    318: "block.glass.step",
    319: "block.grass.break",
    320: "block.grass.fall",
    321: "block.grass.hit",
    322: "block.grass.place",
    323: "block.grass.step",
    324: "block.gravel.break",
    325: "block.gravel.fall",
    326: "block.gravel.hit",
    327: "block.gravel.place",
    328: "block.gravel.step",
    329: "block.grindstone.use",
    330: "entity.guardian.ambient",
    331: "entity.guardian.ambient_land",
    332: "entity.guardian.attack",
    333: "entity.guardian.death",
    334: "entity.guardian.death_land",
    335: "entity.guardian.flop",
    336: "entity.guardian.hurt",
    337: "entity.guardian.hurt_land",
    338: "item.hoe.till",
    339: "entity.hoglin.ambient",
    340: "entity.hoglin.angry",
    341: "entity.hoglin.attack",
    342: "entity.hoglin.converted_to_zombified",
    343: "entity.hoglin.death",
    344: "entity.hoglin.hurt",
    345: "entity.hoglin.retreat",
    346: "entity.hoglin.step",
    347: "block.honey_block.break",
    348: "block.honey_block.fall",
    349: "block.honey_block.hit",
    350: "block.honey_block.place",
    351: "block.honey_block.slide",
    352: "block.honey_block.step",
    353: "item.honey_bottle.drink",
    354: "entity.horse.ambient",
    355: "entity.horse.angry",
    356: "entity.horse.armor",
    357: "entity.horse.breathe",
    358: "entity.horse.death",
    359: "entity.horse.eat",
    360: "entity.horse.gallop",
    361: "entity.horse.hurt",
    362: "entity.horse.jump",
    363: "entity.horse.land",
    364: "entity.horse.saddle",
    365: "entity.horse.step",
    366: "entity.horse.step_wood",
    367: "entity.hostile.big_fall",
    368: "entity.hostile.death",
    369: "entity.hostile.hurt",
    370: "entity.hostile.small_fall",
    371: "entity.hostile.splash",
    372: "entity.hostile.swim",
    373: "entity.husk.ambient",
    374: "entity.husk.converted_to_zombie",
    375: "entity.husk.death",
    376: "entity.husk.hurt",
    377: "entity.husk.step",
    378: "entity.illusioner.ambient",
    379: "entity.illusioner.cast_spell",
    380: "entity.illusioner.death",
    381: "entity.illusioner.hurt",
    382: "entity.illusioner.mirror_move",
    383: "entity.illusioner.prepare_blindness",
    384: "entity.illusioner.prepare_mirror",
    385: "block.iron_door.close",
    386: "block.iron_door.open",
    387: "entity.iron_golem.attack",
    388: "entity.iron_golem.damage",
    389: "entity.iron_golem.death",
    390: "entity.iron_golem.hurt",
    391: "entity.iron_golem.repair",
    392: "entity.iron_golem.step",
    393: "block.iron_trapdoor.close",
    394: "block.iron_trapdoor.open",
    395: "entity.item_frame.add_item",
    396: "entity.item_frame.break",
    397: "entity.item_frame.place",
    398: "entity.item_frame.remove_item",
    399: "entity.item_frame.rotate_item",
    400: "entity.item.break",
    401: "entity.item.pickup",
    402: "block.ladder.break",
    403: "block.ladder.fall",
    404: "block.ladder.hit",
    405: "block.ladder.place",
    406: "block.ladder.step",
    407: "block.lantern.break",
    408: "block.lantern.fall",
    409: "block.lantern.hit",
    410: "block.lantern.place",
    411: "block.lantern.step",
    412: "block.lava.ambient",
    413: "block.lava.extinguish",
    414: "block.lava.pop",
    415: "entity.leash_knot.break",
    416: "entity.leash_knot.place",
    417: "block.lever.click",
    418: "entity.lightning_bolt.impact",
    419: "entity.lightning_bolt.thunder",
    420: "entity.lingering_potion.throw",
    421: "entity.llama.ambient",
    422: "entity.llama.angry",
    423: "entity.llama.chest",
    424: "entity.llama.death",
    425: "entity.llama.eat",
    426: "entity.llama.hurt",
    427: "entity.llama.spit",
    428: "entity.llama.step",
    429: "entity.llama.swag",
    430: "entity.magma_cube.death_small",
    431: "block.lodestone.break",
    432: "block.lodestone.step",
    433: "block.lodestone.place",
    434: "block.lodestone.hit",
    435: "block.lodestone.fall",
    436: "item.lodestone_compass.lock",
    437: "entity.magma_cube.death",
    438: "entity.magma_cube.hurt",
    439: "entity.magma_cube.hurt_small",
    440: "entity.magma_cube.jump",
    441: "entity.magma_cube.squish",
    442: "entity.magma_cube.squish_small",
    443: "block.metal.break",
    444: "block.metal.fall",
    445: "block.metal.hit",
    446: "block.metal.place",
    447: "block.metal_pressure_plate.click_off",
    448: "block.metal_pressure_plate.click_on",
    449: "block.metal.step",
    450: "entity.minecart.inside",
    451: "entity.minecart.riding",
    452: "entity.mooshroom.convert",
    453: "entity.mooshroom.eat",
    454: "entity.mooshroom.milk",
    455: "entity.mooshroom.suspicious_milk",
    456: "entity.mooshroom.shear",
    457: "entity.mule.ambient",
    458: "entity.mule.angry",
    459: "entity.mule.chest",
    460: "entity.mule.death",
    461: "entity.mule.eat",
    462: "entity.mule.hurt",
    463: "music.creative",
    464: "music.credits",
    465: "music_disc.11",
    466: "music_disc.13",
    467: "music_disc.blocks",
    468: "music_disc.cat",
    469: "music_disc.chirp",
    470: "music_disc.far",
    471: "music_disc.mall",
    472: "music_disc.mellohi",
    473: "music_disc.pigstep",
    474: "music_disc.stal",
    475: "music_disc.strad",
    476: "music_disc.wait",
    477: "music_disc.ward",
    478: "music.dragon",
    479: "music.end",
    480: "music.game",
    481: "music.menu",
    482: "music.nether.basalt_deltas",
    483: "music.nether.nether_wastes",
    484: "music.nether.soul_sand_valley",
    485: "music.nether.crimson_forest",
    486: "music.nether.warped_forest",
    487: "music.under_water",
    488: "block.nether_bricks.break",
    489: "block.nether_bricks.step",
    490: "block.nether_bricks.place",
    491: "block.nether_bricks.hit",
    492: "block.nether_bricks.fall",
    493: "block.nether_wart.break",
    494: "item.nether_wart.plant",
    495: "block.stem.break",
    496: "block.stem.step",
    497: "block.stem.place",
    498: "block.stem.hit",
    499: "block.stem.fall",
    500: "block.nylium.break",
    501: "block.nylium.step",
    502: "block.nylium.place",
    503: "block.nylium.hit",
    504: "block.nylium.fall",
    505: "block.nether_sprouts.break",
    506: "block.nether_sprouts.step",
    507: "block.nether_sprouts.place",
    508: "block.nether_sprouts.hit",
    509: "block.nether_sprouts.fall",
    510: "block.fungus.break",
    511: "block.fungus.step",
    512: "block.fungus.place",
    513: "block.fungus.hit",
    514: "block.fungus.fall",
    515: "block.weeping_vines.break",
    516: "block.weeping_vines.step",
    517: "block.weeping_vines.place",
    518: "block.weeping_vines.hit",
    519: "block.weeping_vines.fall",
    520: "block.wart_block.break",
    521: "block.wart_block.step",
    522: "block.wart_block.place",
    523: "block.wart_block.hit",
    524: "block.wart_block.fall",
    525: "block.netherite_block.break",
    526: "block.netherite_block.step",
    527: "block.netherite_block.place",
    528: "block.netherite_block.hit",
    529: "block.netherite_block.fall",
    530: "block.netherrack.break",
    531: "block.netherrack.step",
    532: "block.netherrack.place",
    533: "block.netherrack.hit",
    534: "block.netherrack.fall",
    535: "block.note_block.basedrum",
    536: "block.note_block.bass",
    537: "block.note_block.bell",
    538: "block.note_block.chime",
    539: "block.note_block.flute",
    540: "block.note_block.guitar",
    541: "block.note_block.harp",
    542: "block.note_block.hat",
    543: "block.note_block.pling",
    544: "block.note_block.snare",
    545: "block.note_block.xylophone",
    546: "block.note_block.iron_xylophone",
    547: "block.note_block.cow_bell",
    548: "block.note_block.didgeridoo",
    549: "block.note_block.bit",
    550: "block.note_block.banjo",
    551: "entity.ocelot.hurt",
    552: "entity.ocelot.ambient",
    553: "entity.ocelot.death",
    554: "entity.painting.break",
    555: "entity.painting.place",
    556: "entity.panda.pre_sneeze",
    557: "entity.panda.sneeze",
    558: "entity.panda.ambient",
    559: "entity.panda.death",
    560: "entity.panda.eat",
    561: "entity.panda.step",
    562: "entity.panda.cant_breed",
    563: "entity.panda.aggressive_ambient",
    564: "entity.panda.worried_ambient",
    565: "entity.panda.hurt",
    566: "entity.panda.bite",
    567: "entity.parrot.ambient",
    568: "entity.parrot.death",
    569: "entity.parrot.eat",
    570: "entity.parrot.fly",
    571: "entity.parrot.hurt",
    572: "entity.parrot.imitate.blaze",
    573: "entity.parrot.imitate.creeper",
    574: "entity.parrot.imitate.drowned",
    575: "entity.parrot.imitate.elder_guardian",
    576: "entity.parrot.imitate.ender_dragon",
    577: "entity.parrot.imitate.endermite",
    578: "entity.parrot.imitate.evoker",
    579: "entity.parrot.imitate.ghast",
    580: "entity.parrot.imitate.guardian",
    581: "entity.parrot.imitate.hoglin",
    582: "entity.parrot.imitate.husk",
    583: "entity.parrot.imitate.illusioner",
    584: "entity.parrot.imitate.magma_cube",
    585: "entity.parrot.imitate.phantom",
    586: "entity.parrot.imitate.piglin",
    587: "entity.parrot.imitate.piglin_brute",
    588: "entity.parrot.imitate.pillager",
    589: "entity.parrot.imitate.ravager",
    590: "entity.parrot.imitate.shulker",
    591: "entity.parrot.imitate.silverfish",
    592: "entity.parrot.imitate.skeleton",
    593: "entity.parrot.imitate.slime",
    594: "entity.parrot.imitate.spider",
    595: "entity.parrot.imitate.stray",
    596: "entity.parrot.imitate.vex",
    597: "entity.parrot.imitate.vindicator",
    598: "entity.parrot.imitate.witch",
    599: "entity.parrot.imitate.wither",
    600: "entity.parrot.imitate.wither_skeleton",
    601: "entity.parrot.imitate.zoglin",
    602: "entity.parrot.imitate.zombie",
    603: "entity.parrot.imitate.zombie_villager",
    604: "entity.parrot.step",
    605: "entity.phantom.ambient",
    606: "entity.phantom.bite",
    607: "entity.phantom.death",
    608: "entity.phantom.flap",
    609: "entity.phantom.hurt",
    610: "entity.phantom.swoop",
    611: "entity.pig.ambient",
    612: "entity.pig.death",
    613: "entity.pig.hurt",
    614: "entity.pig.saddle",
    615: "entity.pig.step",
    616: "entity.piglin.admiring_item",
    617: "entity.piglin.ambient",
    618: "entity.piglin.angry",
    619: "entity.piglin.celebrate",
    620: "entity.piglin.death",
    621: "entity.piglin.jealous",
    622: "entity.piglin.hurt",
    623: "entity.piglin.retreat",
    624: "entity.piglin.step",
    625: "entity.piglin.converted_to_zombified",
    626: "entity.piglin_brute.ambient",
    627: "entity.piglin_brute.angry",
    628: "entity.piglin_brute.death",
    629: "entity.piglin_brute.hurt",
    630: "entity.piglin_brute.step",
    631: "entity.piglin_brute.converted_to_zombified",
    632: "entity.pillager.ambient",
    633: "entity.pillager.celebrate",
    634: "entity.pillager.death",
    635: "entity.pillager.hurt",
    636: "block.piston.contract",
    637: "block.piston.extend",
    638: "entity.player.attack.crit",
    639: "entity.player.attack.knockback",
    640: "entity.player.attack.nodamage",
    641: "entity.player.attack.strong",
    642: "entity.player.attack.sweep",
    643: "entity.player.attack.weak",
    644: "entity.player.big_fall",
    645: "entity.player.breath",
    646: "entity.player.burp",
    647: "entity.player.death",
    648: "entity.player.hurt",
    649: "entity.player.hurt_drown",
    650: "entity.player.hurt_on_fire",
    651: "entity.player.hurt_sweet_berry_bush",
    652: "entity.player.levelup",
    653: "entity.player.small_fall",
    654: "entity.player.splash",
    655: "entity.player.splash.high_speed",
    656: "entity.player.swim",
    657: "entity.polar_bear.ambient",
    658: "entity.polar_bear.ambient_baby",
    659: "entity.polar_bear.death",
    660: "entity.polar_bear.hurt",
    661: "entity.polar_bear.step",
    662: "entity.polar_bear.warning",
    663: "block.portal.ambient",
    664: "block.portal.travel",
    665: "block.portal.trigger",
    666: "entity.puffer_fish.ambient",
    667: "entity.puffer_fish.blow_out",
    668: "entity.puffer_fish.blow_up",
    669: "entity.puffer_fish.death",
    670: "entity.puffer_fish.flop",
    671: "entity.puffer_fish.hurt",
    672: "entity.puffer_fish.sting",
    673: "block.pumpkin.carve",
    674: "entity.rabbit.ambient",
    675: "entity.rabbit.attack",
    676: "entity.rabbit.death",
    677: "entity.rabbit.hurt",
    678: "entity.rabbit.jump",
    679: "event.raid.horn",
    680: "entity.ravager.ambient",
    681: "entity.ravager.attack",
    682: "entity.ravager.celebrate",
    683: "entity.ravager.death",
    684: "entity.ravager.hurt",
    685: "entity.ravager.step",
    686: "entity.ravager.stunned",
    687: "entity.ravager.roar",
    688: "block.nether_gold_ore.break",
    689: "block.nether_gold_ore.fall",
    690: "block.nether_gold_ore.hit",
    691: "block.nether_gold_ore.place",
    692: "block.nether_gold_ore.step",
    693: "block.nether_ore.break",
    694: "block.nether_ore.fall",
    695: "block.nether_ore.hit",
    696: "block.nether_ore.place",
    697: "block.nether_ore.step",
    698: "block.redstone_torch.burnout",
    699: "block.respawn_anchor.ambient",
    700: "block.respawn_anchor.charge",
    701: "block.respawn_anchor.deplete",
    702: "block.respawn_anchor.set_spawn",
    703: "entity.salmon.ambient",
    704: "entity.salmon.death",
    705: "entity.salmon.flop",
    706: "entity.salmon.hurt",
    707: "block.sand.break",
    708: "block.sand.fall",
    709: "block.sand.hit",
    710: "block.sand.place",
    711: "block.sand.step",
    712: "block.scaffolding.break",
    713: "block.scaffolding.fall",
    714: "block.scaffolding.hit",
    715: "block.scaffolding.place",
    716: "block.scaffolding.step",
    717: "entity.sheep.ambient",
    718: "entity.sheep.death",
    719: "entity.sheep.hurt",
    720: "entity.sheep.shear",
    721: "entity.sheep.step",
    722: "item.shield.block",
    723: "item.shield.break",
    724: "block.shroomlight.break",
    725: "block.shroomlight.step",
    726: "block.shroomlight.place",
    727: "block.shroomlight.hit",
    728: "block.shroomlight.fall",
    729: "item.shovel.flatten",
    730: "entity.shulker.ambient",
    731: "block.shulker_box.close",
    732: "block.shulker_box.open",
    733: "entity.shulker_bullet.hit",
    734: "entity.shulker_bullet.hurt",
    735: "entity.shulker.close",
    736: "entity.shulker.death",
    737: "entity.shulker.hurt",
    738: "entity.shulker.hurt_closed",
    739: "entity.shulker.open",
    740: "entity.shulker.shoot",
    741: "entity.shulker.teleport",
    742: "entity.silverfish.ambient",
    743: "entity.silverfish.death",
    744: "entity.silverfish.hurt",
    745: "entity.silverfish.step",
    746: "entity.skeleton.ambient",
    747: "entity.skeleton.death",
    748: "entity.skeleton_horse.ambient",
    749: "entity.skeleton_horse.death",
    750: "entity.skeleton_horse.hurt",
    751: "entity.skeleton_horse.swim",
    752: "entity.skeleton_horse.ambient_water",
    753: "entity.skeleton_horse.gallop_water",
    754: "entity.skeleton_horse.jump_water",
    755: "entity.skeleton_horse.step_water",
    756: "entity.skeleton.hurt",
    757: "entity.skeleton.shoot",
    758: "entity.skeleton.step",
    759: "entity.slime.attack",
    760: "entity.slime.death",
    761: "entity.slime.hurt",
    762: "entity.slime.jump",
    763: "entity.slime.squish",
    764: "block.slime_block.break",
    765: "block.slime_block.fall",
    766: "block.slime_block.hit",
    767: "block.slime_block.place",
    768: "block.slime_block.step",
    769: "block.soul_sand.break",
    770: "block.soul_sand.step",
    771: "block.soul_sand.place",
    772: "block.soul_sand.hit",
    773: "block.soul_sand.fall",
    774: "block.soul_soil.break",
    775: "block.soul_soil.step",
    776: "block.soul_soil.place",
    777: "block.soul_soil.hit",
    778: "block.soul_soil.fall",
    779: "particle.soul_escape",
    780: "entity.strider.ambient",
    781: "entity.strider.happy",
    782: "entity.strider.retreat",
    783: "entity.strider.death",
    784: "entity.strider.hurt",
    785: "entity.strider.step",
    786: "entity.strider.step_lava",
    787: "entity.strider.eat",
    788: "entity.strider.saddle",
    789: "entity.slime.death_small",
    790: "entity.slime.hurt_small",
    791: "entity.slime.jump_small",
    792: "entity.slime.squish_small",
    793: "block.smithing_table.use",
    794: "block.smoker.smoke",
    795: "entity.snowball.throw",
    796: "block.snow.break",
    797: "block.snow.fall",
    798: "entity.snow_golem.ambient",
    799: "entity.snow_golem.death",
    800: "entity.snow_golem.hurt",
    801: "entity.snow_golem.shoot",
    802: "entity.snow_golem.shear",
    803: "block.snow.hit",
    804: "block.snow.place",
    805: "block.snow.step",
    806: "entity.spider.ambient",
    807: "entity.spider.death",
    808: "entity.spider.hurt",
    809: "entity.spider.step",
    810: "entity.splash_potion.break",
    811: "entity.splash_potion.throw",
    812: "entity.squid.ambient",
    813: "entity.squid.death",
    814: "entity.squid.hurt",
    815: "entity.squid.squirt",
    816: "block.stone.break",
    817: "block.stone_button.click_off",
    818: "block.stone_button.click_on",
    819: "block.stone.fall",
    820: "block.stone.hit",
    821: "block.stone.place",
    822: "block.stone_pressure_plate.click_off",
    823: "block.stone_pressure_plate.click_on",
    824: "block.stone.step",
    825: "entity.stray.ambient",
    826: "entity.stray.death",
    827: "entity.stray.hurt",
    828: "entity.stray.step",
    829: "block.sweet_berry_bush.break",
    830: "block.sweet_berry_bush.place",
    831: "item.sweet_berries.pick_from_bush",
    832: "enchant.thorns.hit",
    833: "entity.tnt.primed",
    834: "item.totem.use",
    835: "item.trident.hit",
    836: "item.trident.hit_ground",
    837: "item.trident.return",
    838: "item.trident.riptide_1",
    839: "item.trident.riptide_2",
    840: "item.trident.riptide_3",
    841: "item.trident.throw",
    842: "item.trident.thunder",
    843: "block.tripwire.attach",
    844: "block.tripwire.click_off",
    845: "block.tripwire.click_on",
    846: "block.tripwire.detach",
    847: "entity.tropical_fish.ambient",
    848: "entity.tropical_fish.death",
    849: "entity.tropical_fish.flop",
    850: "entity.tropical_fish.hurt",
    851: "entity.turtle.ambient_land",
    852: "entity.turtle.death",
    853: "entity.turtle.death_baby",
    854: "entity.turtle.egg_break",
    855: "entity.turtle.egg_crack",
    856: "entity.turtle.egg_hatch",
    857: "entity.turtle.hurt",
    858: "entity.turtle.hurt_baby",
    859: "entity.turtle.lay_egg",
    860: "entity.turtle.shamble",
    861: "entity.turtle.shamble_baby",
    862: "entity.turtle.swim",
    863: "ui.button.click",
    864: "ui.loom.select_pattern",
    865: "ui.loom.take_result",
    866: "ui.cartography_table.take_result",
    867: "ui.stonecutter.take_result",
    868: "ui.stonecutter.select_recipe",
    869: "ui.toast.challenge_complete",
    870: "ui.toast.in",
    871: "ui.toast.out",
    872: "entity.vex.ambient",
    873: "entity.vex.charge",
    874: "entity.vex.death",
    875: "entity.vex.hurt",
    876: "entity.villager.ambient",
    877: "entity.villager.celebrate",
    878: "entity.villager.death",
    879: "entity.villager.hurt",
    880: "entity.villager.no",
    881: "entity.villager.trade",
    882: "entity.villager.yes",
    883: "entity.villager.work_armorer",
    884: "entity.villager.work_butcher",
    885: "entity.villager.work_cartographer",
    886: "entity.villager.work_cleric",
    887: "entity.villager.work_farmer",
    888: "entity.villager.work_fisherman",
    889: "entity.villager.work_fletcher",
    890: "entity.villager.work_leatherworker",
    891: "entity.villager.work_librarian",
    892: "entity.villager.work_mason",
    893: "entity.villager.work_shepherd",
    894: "entity.villager.work_toolsmith",
    895: "entity.villager.work_weaponsmith",
    896: "entity.vindicator.ambient",
    897: "entity.vindicator.celebrate",
    898: "entity.vindicator.death",
    899: "entity.vindicator.hurt",
    900: "block.vine.step",
    901: "block.lily_pad.place",
    902: "entity.wandering_trader.ambient",
    903: "entity.wandering_trader.death",
    904: "entity.wandering_trader.disappeared",
    905: "entity.wandering_trader.drink_milk",
    906: "entity.wandering_trader.drink_potion",
    907: "entity.wandering_trader.hurt",
    908: "entity.wandering_trader.no",
    909: "entity.wandering_trader.reappeared",
    910: "entity.wandering_trader.trade",
    911: "entity.wandering_trader.yes",
    912: "block.water.ambient",
    913: "weather.rain",
    914: "weather.rain.above",
    915: "block.wet_grass.break",
    916: "block.wet_grass.fall",
    917: "block.wet_grass.hit",
    918: "block.wet_grass.place",
    919: "block.wet_grass.step",
    920: "entity.witch.ambient",
    921: "entity.witch.celebrate",
    922: "entity.witch.death",
    923: "entity.witch.drink",
    924: "entity.witch.hurt",
    925: "entity.witch.throw",
    926: "entity.wither.ambient",
    927: "entity.wither.break_block",
    928: "entity.wither.death",
    929: "entity.wither.hurt",
    930: "entity.wither.shoot",
    931: "entity.wither_skeleton.ambient",
    932: "entity.wither_skeleton.death",
    933: "entity.wither_skeleton.hurt",
    934: "entity.wither_skeleton.step",
    935: "entity.wither.spawn",
    936: "entity.wolf.ambient",
    937: "entity.wolf.death",
    938: "entity.wolf.growl",
    939: "entity.wolf.howl",
    940: "entity.wolf.hurt",
    941: "entity.wolf.pant",
    942: "entity.wolf.shake",
    943: "entity.wolf.step",
    944: "entity.wolf.whine",
    945: "block.wooden_door.close",
    946: "block.wooden_door.open",
    947: "block.wooden_trapdoor.close",
    948: "block.wooden_trapdoor.open",
    949: "block.wood.break",
    950: "block.wooden_button.click_off",
    951: "block.wooden_button.click_on",
    952: "block.wood.fall",
    953: "block.wood.hit",
    954: "block.wood.place",
    955: "block.wooden_pressure_plate.click_off",
    956: "block.wooden_pressure_plate.click_on",
    957: "block.wood.step",
    958: "block.wool.break",
    959: "block.wool.fall",
    960: "block.wool.hit",
    961: "block.wool.place",
    962: "block.wool.step",
    963: "entity.zoglin.ambient",
    964: "entity.zoglin.angry",
    965: "entity.zoglin.attack",
    966: "entity.zoglin.death",
    967: "entity.zoglin.hurt",
    968: "entity.zoglin.step",
    969: "entity.zombie.ambient",
    970: "entity.zombie.attack_wooden_door",
    971: "entity.zombie.attack_iron_door",
    972: "entity.zombie.break_wooden_door",
    973: "entity.zombie.converted_to_drowned",
    974: "entity.zombie.death",
    975: "entity.zombie.destroy_egg",
    976: "entity.zombie_horse.ambient",
    977: "entity.zombie_horse.death",
    978: "entity.zombie_horse.hurt",
    979: "entity.zombie.hurt",
    980: "entity.zombie.infect",
    981: "entity.zombified_piglin.ambient",
    982: "entity.zombified_piglin.angry",
    983: "entity.zombified_piglin.death",
    984: "entity.zombified_piglin.hurt",
    985: "entity.zombie.step",
    986: "entity.zombie_villager.ambient",
    987: "entity.zombie_villager.converted",
    988: "entity.zombie_villager.cure",
    989: "entity.zombie_villager.death",
    990: "entity.zombie_villager.hurt",
    991: "entity.zombie_villager.step",
}

// GetSoundNameByID helper method
func GetSoundNameByID(id SoundID) (string,bool) {
    name, ok := SoundNames[id]
    return name, ok
}
