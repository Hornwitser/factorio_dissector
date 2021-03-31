-- Factorio Game Protocol Dissector
--
-- Reverse engineered from packet captures
-- by Hornwitser


-- Converts a table of key, value pairs into an array of values
function values(iterable)
	local array = {}
	for k, v in pairs(iterable) do
		table.insert(array, v)
	end
	return array
end

dprint = function(...)
	print(table.concat({"Lua:", ...}," "))
end

local default_settings = {
	port = 34197,
}

local pf = {}


local sides = {"Server", "Client"}
local types = {
	[1] = "Handshake",
	[2] = "Authentication",
	[3] = "Sync",

	[6] = "Download",

	[9] = "Empty",
}

pf.flags = ProtoField.uint8("fgp.flags", "Flags", base.HEX, nil, 0, "Frame flags")

pf.flag_side  = ProtoField.bool("fgp.flags.side",       "Side",          8, sides, 0x01, "who is sending?")
pf.flag_type = ProtoField.uint8("fgp.flags.type",       "Type",   base.DEC, types, 0x1e, "packet type")
pf.flag_bit5  = ProtoField.bool("fgp.flags.bit5",       "Mystery flag",  8,   nil, 0x20, "Mystery flag state")
pf.fragmented = ProtoField.bool("fgp.flags.fragmented", "Fragmented",    8,   nil, 0x40, "Whether packet is fragemented")
pf.last_frag  = ProtoField.bool("fgp.flags.last_frag",  "Last Fragment", 8,   nil, 0x80, "Last packet fragment")


pf.frag_id = ProtoField.uint16("fgp.frag.msg_id", "Message ID",        base.DEC,   nil, 0x7fff, "Message ID fragment belongs to")
pf.frag_north_flag = ProtoField.bool("fgp.frag.north", "North", 16, nil, 0x8000, "North flag")
pf.frag_seq = ProtoField.uint8("fgp.frag.seq",    "Fragment sequence", base.DEC,   nil, 0, "Fragment sequence number")
pf.frag_data = ProtoField.bytes("fgp.frag.data",  "Fragment data",     base.SPACE, "Fragment content")

pf.frag_north_count = ProtoField.uint8("fgp.frag.north_count", "North count", base.DEC, nil, 0, "North count")
pf.frag_north_data = ProtoField.bytes("fgp.frag.north_data", "North Data", base.SPACE, "North Data")

pf.fragment  = ProtoField.framenum("fgp.fragment", "Fragment",base.NONE, frametype.NONE, 0, "Fragment")
pf.fragments = ProtoField.bytes("fgp.fragments", "Fragments", base.SPACE, "Fragments")


pf.sync_flags = ProtoField.uint8("fgp.sync_flags", "Sync Flags", base.HEX, nil, 0, "Sync Packet flags")
pf.sync_flag_strange = ProtoField.bool("fgp.sync_flags.strange", "Strange data",         8, nil, 0x01)
pf.sync_flag_gametick = ProtoField.bool("fgp.sync_flags.gametick",  "Has Gametick", 8, nil, 0x02, "Packet contains gametick data")
pf.sync_flag_one_tick = ProtoField.bool("fgp.sync_flags.one_tick", "Only one Tick",         8, nil, 0x04)
pf.sync_flag_no_data = ProtoField.bool("fgp.sync_flags.no_data", "No gametick data",         8, nil, 0x08)
pf.sync_flag_weird_data = ProtoField.bool("fgp.sync_flags.weird_data", "Weird data",         8, nil, 0x10)
pf.sync_flag_bit5 = ProtoField.bool("fgp.sync_flags.bit5", "Bit5",         8, nil, 0x20)
pf.sync_flag_bit6 = ProtoField.bool("fgp.sync_flags.bit6", "Bit6",         8, nil, 0x40)
pf.sync_flag_bit7 = ProtoField.bool("fgp.sync_flags.bit7", "Bit7",         8, nil, 0x80)


pf.tick_seq = ProtoField.uint32("fgp.tick_seq", "Sync Sequence", base.DEC, nil, 0, "Sync packet sequence number")
pf.server_gameticks_count = ProtoField.uint8("fgp.server_gametick_count", "Gameticks", base.DEC, nil, 0, "Number of gameticks in packet")

pf.server_gametick = ProtoField.bytes("fgp.server_gametick", "Gametick", base.SPACE, "Data for a server gametick")
pf.server_gametick_tick    = ProtoField.uint32("fgp.server_gametick.tick",  "Server Gametick Tick",   base.DEC, nil, 0, "Server Gametick")

pf.strange_count = ProtoField.uint8("fgp.strange.count", "Strange Count", base.DEC, nil, 0, "Number of strange data")
pf.strange_data = ProtoField.uint32("fgp.strange.data", "Strange Data", base.DEC, nil, 0, "Strange data")

pf.gametick_odd = ProtoField.bytes("fgp.gametick.odd", "Odd", base.SPACE, "Odd")
pf.gametick_odd_count          = ProtoField.uint8("fgp.gametick.odd_count", "Odd count", base.DEC, nil, 0, "Odd count")
pf.gametick_odd_id            = ProtoField.uint8("fgp.gametick.odd_id", "Odd ID", base.HEX, nil, 0, "Odd id")
pf.gametick_odd_blue          = ProtoField.uint32("fgp.gametick.odd_blue", "Odd Blue", base.HEX, nil, 0, "Odd blue")
pf.gametick_odd_green         = ProtoField.uint8("fgp.gametick.odd_green", "Odd Green", base.HEX, nil, 0, "Odd green")
pf.gametick_odd_total_length  = ProtoField.uint32("fgp.gametick.odd_total_length", "Odd total length", base.HEX, nil, 0, "Odd total length")
pf.gametick_odd_segment_start = ProtoField.uint32("fgp.gametick.odd_segment_start", "Odd segment start", base.HEX, nil, 0, "Odd segment start")
pf.gametick_odd_length        = ProtoField.uint32("fgp.gametick.odd_length", "Odd length", base.HEX, nil, 0, "Odd length")
pf.gametick_odd_payload = ProtoField.bytes("fgp.gametick.odd_payload", "Odd Payload", base.SPACE, "Odd Payload")

pf.gametick_pebble_count = ProtoField.uint8("fgp.gametick.pebble_count", "Gametick Pebble Count", base.DEC, nil, 0, "Number of gametick data pebbles")
pf.gametick_pebble       = ProtoField.bytes("fgp.gametick.pebble", "Gametick Pebble", base.SPACE, "Small bit of data for a gametick")
pf.gametick_pebble_id    = ProtoField.uint8("fgp.gametick.pebble.id", "Gametick Pebble ID", base.HEX, nil, 0, "Pebble ID of gametick data")

--pf.server_gametick_checksum = ProtoField.uint32("fgp.server_gametick.checksum", "Checksum",   base.HEX, nil, 0, "Checksum of server gametick")
--pf.server_gametick_end      = ProtoField.uint32("fgp.server_gametick.end",      "Tick End",   base.DEC, nil, 0, "End tick of server gametick")
local gametick_pebbles = {
	[0x01] = {len=1},
	[0x02] = {len=1},
	[0x03] = {len=1},
	[0x04] = {len=1},
	[0x05] = {len=1},
	[0x06] = {len=1},
	[0x07] = {len=1},
	[0x08] = {len=1},
	[0x09] = {len=1},
	[0x0a] = {len=1},
	[0x0b] = {len=1},
	[0x0c] = {len=1},
	[0x0d] = {len=1},

	[0x0f] = {len=1},
	[0x10] = {len=1},
	[0x11] = {len=1},
	[0x12] = {len=1},
	[0x13] = {len=1},
	[0x14] = {len=1},
	[0x15] = {len=1},
	[0x16] = {len=1},
	[0x17] = {len=1},

	[0x19] = {len=1},

	[0x1b] = {len=1},
	[0x1c] = {len=1},
	[0x1d] = {len=1},
	[0x1e] = {len=1},
	[0x1f] = {len=1},
	[0x20] = {len=1},

	[0x25] = {len=1},

	[0x29] = {len=1},
	[0x2a] = {len=1},
	[0x2b] = {len=1},

	[0x2f] = {len=1},

	[0x31] = {len=1},

	[0x35] = {len=1},
	[0x36] = {len=9},
	[0x37] = {len=14},
	[0x38] = {len=2},
	[0x39] = {len=9},
	[0x3a] = {len=3},
	[0x3b] = {len=6},

	[0x3e] = {len=6},
	[0x3f] = {len=6},
	[0x40] = {len=6},
	[0x41] = {len=6},
	[0x42] = {len=9}, -- Tick checksum
	[0x43] = {len=7},

	[0x45] = {len=10},
	[0x46] = {len=3},
	[0x47] = {len=9},
	[0x48] = {len=5},
	[0x49] = {len=9}, -- was 6
	[0x4a] = {len=6},
	[0x4b] = {len=5},
	[0x4c] = {len=8},

	[0x50] = {len=3},
	[0x51] = {len=9},

	[0x54] = {len=10},

	[0x59] = {len=2},
	[0x5a] = {len=13},

	[0x5d] = {len=18},

	[0x5e] = {len=10},
	[0x5f] = {len=10},

	[0x60] = {len=9},

	[0x62] = {len=6},
	[0x63] = {len=2},

	[0x65] = {len=9},

	[0x68] = {len=24},

	[0x61] = {len=26},

	[0x6a] = {len=24},

	[0x6c] = {len=16}, -- Variable length

	[0x6f] = {len=7},
	[0x70] = {len=7},

	[0x72] = {len=7},
	[0x73] = {len=9},

	[0x75] = {len=3},

	[0x7e] = {len=8}, -- usually contains a name

	[0x86] = {len=14},
	[0x87] = {len=11},

	[0x8b] = {len=17},
	[0x8c] = {len=7},

	[0x8f] = {len=2}, -- usually /silent-command.  rcon?
	[0x90] = {len=6},

	[0x98] = {len=17}, -- Map marker
	[0x9f] = {len=13}, -- Seems to be variable length

	[0xa2] = {len=5},

	[0xa6] = {len=9},
	[0xa7] = {len=8},
	[0xa8] = {len=5},
	[0xa9] = {len=3},
	[0xaa] = {len=2},

	[0xb0] = {len=2},
	[0xb1] = {len=2},
	[0xb2] = {len=3},
	[0xb3] = {len=5},
	[0xb4] = {len=5},

	[0xbc] = {len=2},
	[0xbd] = {len=2},

	[0xbe] = {len=2},
	[0xbf] = {len=2},

	[0xc5] = {len=5},

	[0xce] = {len=9},
	[0xcf] = {len=2},

	[0xd1] = {len=9},
	[0xd2] = {len=2},

	[0xd9] = {len=2},
}

for id, info in pairs(gametick_pebbles) do
	local name = string.format("Pebble 0x%x", id)
	local desc = string.format("Gametick Pebble 0x%x Data", id)
	pf["gametick_pebble_"..id] = ProtoField.bytes("fgp.gametick.pebble.data_"..id, name, base.SPACE, desc)
end


pf.weird_pebble_count = ProtoField.uint8("fgp.weird.pebble_count", "Weird Pebble Count", base.DEC, nil, 0, "Number of weird data pebbles")
pf.weird_pebble       = ProtoField.bytes("fgp.weird.pebble", "Weird Pebble", base.SPACE, "Small bit of data for a sync packet")
pf.weird_pebble_id    = ProtoField.uint8("fgp.weird.pebble.id", "Weird Pebble ID", base.HEX, nil, 0, "Pebble ID of weird data")

pf.monster = ProtoField.bytes("fgp.weird.monster", "Weird Monster", base.SPACE, "Weird Monster Struct")
pf.monster_goblin = ProtoField.uint32("fgp.weird.monster.goblin", "Monster Goblin", base.DEC, nil, 0, "Monster Goblin")
pf.monster_zombie = ProtoField.uint32("fgp.weird.monster.zombie", "Monster Zombie", base.DEC, nil, 0, "Monster Zombie")
pf.monster_tick = ProtoField.uint32("fgp.weird.monster.tick", "Monster Tick", base.DEC, nil, 0, "Monster Tick")
pf.monster_hydra = ProtoField.uint32("fgp.weird.monster.hydra", "Monster Hydra", base.DEC, nil, 0, "Monster Hydra")
pf.monster_gryphon = ProtoField.uint32("fgp.weird.monster.gryphon", "Monster Gryphon", base.DEC, nil, 0, "Monster Gryphon")
pf.monster_gnome = ProtoField.uint16("fgp.weird.monster.gnome", "Monster Gnome", base.DEC, nil, 0, "Monster Gnome")
pf.monster_bat = ProtoField.bytes("fgp.weird.monster.bat", "Weird Monster Bat", base.SPACE, "Weird Monster Bat")
pf.monster_bat_count = ProtoField.uint8("fgp.weird.monster.bat.count", "Monster Bat Count", base.DEC, nil, 0, "Monster Bat Count")
pf.monster_bat_len = ProtoField.uint8("fgp.weird.monster.bat.len", "Monster Bat len", base.DEC, nil, 0, "Monster Bat len")
pf.monster_bat_string = ProtoField.string("fgp.weird.monster.bat.string", "Monster Bat string", base.ASCII, "Monster Bat string")
pf.monster_horse = ProtoField.uint16("fgp.weird.monster.horse", "Monster Horse", base.DEC, nil, 0, "Monster Horse")
pf.monster_dog = ProtoField.bytes("fgp.weird.monster.dog", "Weird Monster Dog", base.SPACE, "Weird Monster Dog")
pf.monster_dog_count = ProtoField.uint8("fgp.weird.monster.dog.count", "Monster Dog Count", base.DEC, nil, 0, "Monster Dog Count")
pf.monster_dog_len = ProtoField.uint8("fgp.weird.monster.dog.len", "Monster Dog len", base.DEC, nil, 0, "Monster Dog len")
pf.monster_dog_string = ProtoField.string("fgp.weird.monster.dog.string", "Monster Dog string", base.ASCII, "Monster Dog string")
pf.monster_ghoul = ProtoField.bytes("fgp.weird.monster.ghoul", "Weird Monster Ghoul", base.SPACE, "Weird Monster Ghoul")
pf.monster_ghoul_count = ProtoField.uint8("fgp.weird.monster.ghoul.count", "Monster Ghoul Count", base.DEC, nil, 0, "Monster Ghoul Count")
pf.monster_ghoul_item = ProtoField.uint8("fgp.weird.monster.ghoul.item", "Monster Ghoul Item", base.DEC, nil, 0, "Monster Ghoul Item")
pf.monster_undead = ProtoField.bytes("fgp.weird.monster.undead", "Weird Monster Undead", base.SPACE, "Weird Monster Undead")
pf.monster_undead_count = ProtoField.uint8("fgp.weird.monster.undead.count", "Monster Undead Count", base.DEC, nil, 0, "Monster Undead Count")
pf.monster_undead_item = ProtoField.uint8("fgp.weird.monster.undead.item", "Monster Undead Item", base.DEC, nil, 0, "Monster Undead Item")
pf.monster_snake = ProtoField.uint24("fgp.weird.monster.snake", "Monster Snake", base.DEC, nil, 0, "Monster Snake")
pf.monster_worm = ProtoField.bytes("fgp.weird.monster.worm", "Weird Monster Worm", base.SPACE, "Weird Monster Worm")
pf.monster_worm_count = ProtoField.uint8("fgp.weird.monster.worm.count", "Monster Worm Count", base.DEC, nil, 0, "Monster Worm Count")
pf.monster_worm_len = ProtoField.uint8("fgp.weird.monster.worm.len", "Monster Worm len", base.DEC, nil, 0, "Monster Worm len")
pf.monster_worm_string = ProtoField.string("fgp.weird.monster.worm.string", "Monster Worm string", base.ASCII, "Monster Worm string")
pf.monster_rat = ProtoField.bytes("fgp.weird.monster.rat", "Weird Monster Rat", base.SPACE, "Weird Monster Rat")
pf.monster_rat_count = ProtoField.uint8("fgp.weird.monster.rat.count", "Monster Rat Count", base.DEC, nil, 0, "Monster Rat Count")
pf.monster_rat_len = ProtoField.uint8("fgp.weird.monster.rat.len", "Monster Rat len", base.DEC, nil, 0, "Monster Rat len")
pf.monster_rat_string = ProtoField.string("fgp.weird.monster.rat.string", "Monster Rat string", base.ASCII, "Monster Rat string")
pf.monster_cat = ProtoField.uint16("fgp.weird.monster.cat", "Monster Cat", base.DEC, nil, 0, "Monster Cat")

local weird_pebbles = {
	[0x01] = {        slen=3},
	[0x02] = {        slen=3},
	[0x03] = {clen=1},
	[0x04] = {        slen=6},
	[0x05] = {        slen=0}, -- Monster data

	[0x06] = {clen=1, slen=3},
	[0x07] = {        slen=3},
	[0x08] = {        slen=2},
	[0x09] = {clen=1, slen=3},
	[0x0a] = {clen=1, slen=3},
	[0x0b] = {        slen=3},



	[0x0f] = {        slen=6},
	[0x10] = {clen=4, slen=4},
	[0x11] = {        slen=3},
	[0x12] = {clen=5},
}

for id, info in pairs(weird_pebbles) do
	local name = string.format("Pebble 0x%x", id)
	local desc = string.format("Weird Pebble 0x%x Data", id)
	pf["weird_pebble_"..id] = ProtoField.bytes("fgp.weird.pebble.data_"..id, name, base.SPACE, desc)
end


pf.client_gameticks_flags     = ProtoField.uint8("fgp.client_gameticks_flags",      "Gameticks Flags",   base.HEX, nil, 0, "Flags for client gameticks")
pf.client_gameticks_count     = ProtoField.uint8("fgp.client_gameticks_count",      "Gametick count",   base.HEX, nil, 0, "Number of client gameticks")

pf.client_gametick = ProtoField.bytes("fgp.client_gametick", "Gametick", base.SPACE, "Data for a client gametick")
pf.client_gametick_tick     = ProtoField.uint32("fgp.client_gametick.tick",      "Tick",   base.DEC, nil, 0, "Tick number of client gametick")
pf.client_gametick_timeshift = ProtoField.uint32("fgp.client_gametick.timeshift", "Timeshift Tick",   base.DEC, nil, 0, "Latency hiding tick of client gametick")


pf.download_seq  = ProtoField.uint32("fgp.download_seq", "Download Sequence", base.DEC, nil, 0, "download packet sequence")
pf.download_data = ProtoField.bytes("fgp.download_data", "Download Data", base.NONE, "download packet data")

pf.unknown = ProtoField.bytes("fgp.unknown", "Unknown Data", base.SPACE, "Undecoded Data")


local fgp = Proto("fgp", "Factorio Game Protocol")
fgp.fields = values(pf)

-- Fields
local type_field         = Field.new("fgp.flags.type")
local side_field         = Field.new("fgp.flags.side")
local tick_seq_field     = Field.new("fgp.tick_seq")
local download_seq_field = Field.new("fgp.download_seq")
local fragmented_field   = Field.new("fgp.flags.fragmented")
local last_frag_field    = Field.new("fgp.flags.last_frag")

local frag_north_field = Field.new("fgp.frag.north")
local frag_id_field    = Field.new("fgp.frag.msg_id")
local frag_seq_field   = Field.new("fgp.frag.seq")

local sync_flag_strange_field    = Field.new("fgp.sync_flags.strange")
local sync_flag_gametick_field   = Field.new("fgp.sync_flags.gametick")
local sync_flag_one_tick_field   = Field.new("fgp.sync_flags.one_tick")
local sync_flag_no_data_field    = Field.new("fgp.sync_flags.no_data")
local sync_flag_weird_data_field = Field.new("fgp.sync_flags.weird_data")

-- Field shortcuts
local function is_client()
	return not side_field()()
end

local function is_server()
	return side_field()()
end

-- Expert info
local ef = {}
ef.too_short   = ProtoExpert.new("fgp.too_short.expert", "Factorio Game Protocol packet too short", expert.group.MALFORMED, expert.severity.ERROR)
ef.unknown     = ProtoExpert.new("fgp.unknown.expert", "Factorio Game Protocol unknown packet data", expert.group.UNDECODED, expert.severity.WARN)
ef.malformed   = ProtoExpert.new("fgp.malformed.expert", "Factorio Game Protocol malformed data", expert.group.MALFORMED, expert.severity.ERROR)
ef.unnecessary = ProtoExpert.new("fgp.unnecessary.expert", "Factorio Game PRotocol unnecessary encoding", expert.group.PROTOCOL, expert.severity.NOTE)
fgp.experts = values(ef)


-- Partial packet fragments data
-- This is an table of msg_id to fragment data
local fragments = {}

-- fragment_data_format = {
--     state = "bulid" or "end" or "complete",
--     last_seq = frag_seq of last fragment
--     parts = {
--         [frag_seq] = {
--             bytes = ByteBuffer,
--             len = length of the bytes
--             number = packet number it was first observed in
--         }
--     }
-- }


-- Forward declarations
local payload_dissector
local dissect_gametick_pebbles
local decode_uint32v

function fgp.init()
	fragments = {}
end

function fgp.dissector(tvbuf, pktinfo, root)
	pktinfo.cols.protocol:set("Factorio")
	local pktlen = tvbuf:reported_length_remaining()
	local tree = root:add(fgp, tvbuf:range(0, pktlen))
	local pos = 0

	if pktlen < 1 then
		pktinfo.cols.info:set("[Malformed] Empty")
		tree:add_proto_expert_info(ef.too_short)
		return
	end

	local flagrange = tvbuf:range(pos, 1)
	pos = pos + 1
	local flag_tree = tree:add(pf.flags, flagrange)
	flag_tree:add(pf.flag_side, flagrange)
	flag_tree:add(pf.flag_type, flagrange)
	flag_tree:add(pf.flag_bit5, flagrange)
	flag_tree:add(pf.fragmented, flagrange)
	flag_tree:add(pf.last_frag, flagrange)

	pktinfo.cols.info:set(side_field()() and "S → " or "C → ")

	if fragmented_field()() then
		if pktlen < 4 then
			pktinfo.cols.info:append("[Too short] ")
			tree:add_proto_expert_info(
				ef.too_short, "Packet too short for fragment header"
			)

			return
		end

		local last = last_frag_field()()

		tree:add_le(pf.frag_id, tvbuf:range(pos, 2))
		tree:add_le(pf.frag_north_flag, tvbuf:range(pos, 2))
		pos = pos + 2

		tree:add(pf.frag_seq, tvbuf:range(pos, 1))
		pos = pos + 1

		-- Check reassembly
		local north = frag_north_field()()
		local msg_id = frag_id_field()()
		local seq = frag_seq_field()()

		-- Server and client ids can overlap
		if is_server() then
			msg_id = msg_id + 0x00010000
		end

		-- XXX is north part of payload data, or fragment header?
		if north then
			tree:add(pf.frag_north_count, tvbuf:range(pos, 1))
			local count = tvbuf:range(pos, 1):uint()
			pos = pos + 1

			for _=1, count do
				tree:add(pf.frag_north_data, tvbuf:range(pos, 4))
				pos = pos + 4
			end
		end

		-- Check if packet is fragmented without fragments
		-- This usually happens to give north information
		if seq == 0 and last then
			if not north then
				tree:add_proto_expert_info(
					ef.unnecessary, "Fragmented packet without fragments or north"
				)
			end

			-- Skip reassembly and decode normally
			payload_dissector(tvbuf:range(pos), pktinfo, tree)
			return
		end

		tree:add(
			"Fragment Data ("..(pktlen - pos).." bytes)",
			pf.frag_data, tvbuf:range(pos, pktlen - pos)
		)

		if fragments[msg_id] == nil then
			fragments[msg_id] = {
				state = "build",
				parts = {
					[seq] = {
						bytes = tvbuf:range(pos, pktlen - pos):bytes(),
						len = pktlen - pos,
						number = pktinfo.number,
					}
				}
			}
		end

		local msg = fragments[msg_id]
		if msg.state ~= "complete" then
			if msg.parts[seq] == nil then
				if last then
					msg.state = "end"
					msg.last_seq = seq
				end

				msg.parts[seq] = {
					bytes = tvbuf:range(pos, pktlen - pos):bytes(),
					len = pktlen - pos,
					number = pktinfo.number,
				}
			end

			-- check if complete
			if msg.state == "end" then
				local all = true
				for i=0,msg.last_seq do
					if msg.parts[i] == nil then
						all = false
						break
					end
				end

				if all then
					msg.state = "complete"
					local all_bytes = ByteArray.new()
					for i=0,msg.last_seq do
						all_bytes:append(msg.parts[i].bytes)
						msg.parts[i].bytes = nil
					end

					msg.bytes = all_bytes
				end
			end
		end

		if msg.parts[seq].number ~= pktinfo.number then
			pktinfo.cols.info:prepend("[Retransmission] ")
			-- TODO add expert info
		end

		tree.text =
			"Factorio Game Protocol" .. (last and " Last" or "") ..
			" Fragment, Msg: " .. frag_id_field().display .. ", Seq: "
			.. frag_seq_field().display .. ", Len: " .. pktlen - pos

		-- It might have been completed now, reasseble if so
		if last and msg.state == "complete" then
			local tvb = msg.bytes:tvb("Reassembled Payload")
			local frags_tree = root:add(
				pf.fragments, tvb:range()
			)
			frags_tree.generated = true
			frags_tree.text =
				(msg.last_seq + 1) .. " Reassembled Fragments ("
				.. tvb:len().." bytes)"

			local payload_pos = 0
			for i=0,msg.last_seq do
				part = msg.parts[i]
				local frag_item = frags_tree:add(
					pf.fragment, tvb:range(payload_pos, part.len), part.number
				)
				frag_item.generated = true
				frag_item.text =
					"Fragment: " .. part.number .. " (" .. part.len .." bytes)"
				payload_pos = payload_pos + part.len
			end

			local tree = root:add(fgp, tvb:range())
			payload_dissector(tvb, pktinfo, tree)

		-- Either incomplete or a fragment, show info
		else
			if last then
				pktinfo.cols.info:append("Last ")
			end
			pktinfo.cols.info:append(
				"Frag Msg=" .. frag_id_field().display
				.. " Seq=" .. frag_seq_field().display
				.. " Len=" .. pktlen - pos
			)
		end

	-- last frag set while fragment is unset
	elseif last_frag_field()() then
		pktinfo.cols.info:prepend("[Unknown]")
		tree:add_proto_expert_info(
			ef.unknown, "Last Fragment flag set without Fragment flag"
		)

	else
		-- Not fragmented, decode normally
		payload_dissector(tvbuf:range(1), pktinfo, tree)
	end
end

function payload_dissector(tvbuf, pktinfo, tree)
	local pktlen = tvbuf:len()
	local pos = 0

	local pktype = type_field()()

	if pktype == 1 then -- Handshake
		pktinfo.cols.info:append("Handshake")
		-- TODO

	elseif pktype == 2 then -- Authorization
		pktinfo.cols.info:append("Authorization")
		-- TODO

	elseif pktype == 3 then -- Sync Packet
		--- XXX DEBUG
		--if not side_field()() and pktinfo.visited then -- client
			--print(tvbuf:bytes():tohex(true))
		--end

		if pktlen < 1 then
			pktinfo.cols.info:prepend("[Too short] ")
			tree:add_proto_expert_info(ef.too_short)
			return
		end

		local sync_flags_range = tvbuf:range(pos, 1)
		local sync_flags_tree = tree:add(pf.sync_flags, sync_flags_range)
		pos = pos + 1

		sync_flags_tree:add(pf.sync_flag_strange, sync_flags_range)
		sync_flags_tree:add(pf.sync_flag_gametick, sync_flags_range)
		sync_flags_tree:add(pf.sync_flag_one_tick, sync_flags_range)
		sync_flags_tree:add(pf.sync_flag_no_data, sync_flags_range)
		sync_flags_tree:add(pf.sync_flag_weird_data, sync_flags_range)
		sync_flags_tree:add(pf.sync_flag_bit5, sync_flags_range)
		sync_flags_tree:add(pf.sync_flag_bit6, sync_flags_range)
		sync_flags_tree:add(pf.sync_flag_bit7, sync_flags_range)

		if pktlen < pos + 4 then
			pktinfo.cols.info:prepend("[Too short] ")
			tree:add_proto_expert_info(ef.too_short)
			return
		end

		tree:add_le(pf.tick_seq, tvbuf:range(pos, 4))
		pos = pos + 4
		pktinfo.cols.info:append("Sync Seq="..tick_seq_field().display)

		local gametick_data = not sync_flag_no_data_field()()
		local gametick_count = nil

		if not sync_flag_gametick_field()() then
			gametick_count = 0

		elseif sync_flag_one_tick_field()() then
			gametick_count = 1
		end

		if gametick_count == nil then
			tree:add(pf.server_gameticks_count, tvbuf(pos, 1))
			gametick_count = tvbuf(pos, 1):uint()
			pos = pos + 1
		else
			local count_item =
				tree:add(pf.server_gameticks_count, gametick_count)
			count_item.generated = true
		end

		local hit_unknown = false
		for _=1,gametick_count do
			local tick_tree = tree:add(pf.server_gametick, tvbuf:range(pos))
			local start_pos = pos

			tick_tree:add_le(pf.server_gametick_tick, tvbuf:range(pos, 4))
			pos = pos + 4

			if gametick_data then
				pos, hit_unknown = dissect_gametick_pebbles(pos, tvbuf, pktinfo, tick_tree)

				if hit_unknown then
					break
				end
			end

			tick_tree.len = pos - start_pos
		end

		if is_client() then
			tree:add_le(pf.client_gametick_timeshift, tvbuf:range(pos, 4))
			pos = pos + 4
		end

		if sync_flag_weird_data_field()() then
			pos, hit_unknown = dissect_weird_pebbles(pos, tvbuf, pktinfo, tree)
		end

		if sync_flag_strange_field()() then
			tree:add(pf.strange_count, tvbuf:range(pos, 1))
			pos = pos + 1
			for _=1,tvbuf:range(pos - 1, 1):uint() do
				tree:add_le(pf.strange_data, tvbuf:range(pos, 4))
				pos = pos + 4
			end
		end

	elseif pktype == 6 then -- Download Packet
		if pktlen < 4 then
			tree:add_proto_expert_info(ef.too_short)
			return
		end
		tree:add_le(pf.download_seq, tvbuf:range(pos, 4))
		pos = pos + 4

		-- Client doesn't send any data, server always does
		local has_data = pktlen > 4
		if is_client() and has_data then
			pktinfo.cols.info:prepend("[Unknown] ")
			tree:add_proto_expert_info(
				ef.unknown, "Client download packet with data"
			)

		elseif is_server() and not has_data then
			pktinfo.cols.info:prepend("[Unknown] ")
			tree:add_proto_expert_info(
				ef.unknown, "Server download packet without data"
			)
		end

		if has_data then
			tree:add(pf.download_data, tvbuf:range(pos, pktlen-pos))
			pos = pktlen
		end

		pktinfo.cols.info:append(
			"Download" .. (has_data and " Seq=" or " Req=")
			.. download_seq_field()()
		)

	elseif pktype == 9 then -- Empty packet
		pktinfo.cols.info:append("Empty")

	else
		tree:add_proto_expert_info(ef.unknown)
		pktinfo.cols.info:append("Unknown type "..pktype)
	end

	if pos ~= pktlen then
		local item = tree:add(pf.unknown, tvbuf:range(pos, pktlen - pos))
		item:add_proto_expert_info(ef.unknown, "Unknown payload data")
		pktinfo.cols.info:prepend("[Unknown Data] ")
	end
end

function dissect_weird_pebbles(pos, tvbuf, pktinfo, tree)
	if pos + 1 > tvbuf:len() then
		pktinfo.cols.info:prepend("[Too short] ")
		tree:add_proto_expert_info(
			ef.too_short, "Packet too short for weird pebble count"
		)
		return pos, true
	end

	local count_range = tvbuf:range(pos, 1)
	pos = pos + 1

	local count = count_range:uint()
	if count == 0xff then
		count_range = tvbuf:range(pos, 4)
		count = count_range:le_uint()
		pos = pos + 4
	end

	tree:add(pf.weird_pebble_count, count_range)

	local hit_unknown = false
	for _=1, count do
		if pos + 1 > tvbuf:len() then
			pktinfo.cols.info:prepend("[Too short] ")
			tree:add_proto_expert_info(
				ef.too_short, "Packet too short for weird pebble"
			)
			return pos, true
		end

		local id_range = tvbuf:range(pos, 1)
		tree:add(pf.weird_pebble_id, id_range)
		pos = pos + 1

		local id = id_range:uint()
		if weird_pebbles[id] ~= nil then
			local info = weird_pebbles[id]
			local len
			if is_client() then
				len = info.clen
			else
				len = info.slen
			end

			if len == nil then
				pktinfo.cols.info:prepend("[Weird Unknown Side] ")
				tree:add_proto_expert_info(
					ef.unknown, "Unknown weird pebble id for side "..id
				)
				hit_unknown = true
				break
			end

			if id == 0x02 then
				len = len + tvbuf:range(pos, 1):uint()
			end

			if id == 0x05 then
				local monster_start_pos = pos
				local monster_tree = tree:add(pf.monster, tvbuf:range(pos))

				monster_tree:add_le(pf.monster_goblin, tvbuf:range(pos, 4))
				pos = pos + 4
				monster_tree:add_le(pf.monster_zombie, tvbuf:range(pos, 4))
				pos = pos + 4
				monster_tree:add_le(pf.monster_tick, tvbuf:range(pos, 4))
				pos = pos + 4
				monster_tree:add_le(pf.monster_hydra, tvbuf:range(pos, 4))
				pos = pos + 4
				monster_tree:add_le(pf.monster_gryphon, tvbuf:range(pos, 4))
				pos = pos + 4
				monster_tree:add_le(pf.monster_gnome, tvbuf:range(pos, 2))
				pos = pos + 2

				local bat_start_pos = pos
				local bat_tree = monster_tree:add(pf.monster_bat, tvbuf:range(pos))
				bat_tree:add(pf.monster_bat_count, tvbuf:range(pos, 1))
				local bat_count = tvbuf:range(pos, 1):uint()
				pos = pos + 1

				for _=1, bat_count do
					bat_tree:add(pf.monster_bat_len, tvbuf:range(pos, 1))
					local bat_len = tvbuf:range(pos, 1):uint()
					pos = pos + 1

					bat_tree:add(pf.monster_bat_string, tvbuf:range(pos, bat_len))
					pos = pos + bat_len
				end
				bat_tree.len = pos - bat_start_pos

				monster_tree:add_le(pf.monster_horse, tvbuf:range(pos, 4))
				pos = pos + 4

				local dog_start_pos = pos
				local dog_tree = monster_tree:add(pf.monster_dog, tvbuf:range(pos))
				dog_tree:add(pf.monster_dog_count, tvbuf:range(pos, 1))
				local dog_count = tvbuf:range(pos, 1):uint()
				pos = pos + 1

				for _=1, dog_count do
					dog_tree:add(pf.monster_dog_len, tvbuf:range(pos, 1))
					local dog_len = tvbuf:range(pos, 1):uint()
					pos = pos + 1

					dog_tree:add(pf.monster_dog_string, tvbuf:range(pos, dog_len))
					pos = pos + dog_len
				end
				dog_tree.len = pos - dog_start_pos

				local ghoul_start_pos = pos
				local ghoul_tree = monster_tree:add(pf.monster_ghoul, tvbuf:range(pos))
				ghoul_tree:add(pf.monster_ghoul_count, tvbuf:range(pos, 1))
				local ghoul_count = tvbuf:range(pos, 1):uint()
				pos = pos + 1

				for _=1, ghoul_count do
					ghoul_tree:add_le(pf.monster_ghoul_item, tvbuf:range(pos, 4))
					pos = pos + 4
				end
				ghoul_tree.len = pos - ghoul_start_pos

				local undead_start_pos = pos
				local undead_tree = monster_tree:add(pf.monster_undead, tvbuf:range(pos))
				undead_tree:add(pf.monster_undead_count, tvbuf:range(pos, 1))
				local undead_count = tvbuf:range(pos, 1):uint()
				pos = pos + 1

				for _=1, undead_count do
					undead_tree:add_le(pf.monster_undead_item, tvbuf:range(pos, 4))
					pos = pos + 4
				end
				undead_tree.len = pos - undead_start_pos

				monster_tree:add_le(pf.monster_snake, tvbuf:range(pos, 3))
				pos = pos + 3

				local worm_start_pos = pos
				local worm_tree = monster_tree:add(pf.monster_worm, tvbuf:range(pos))
				worm_tree:add(pf.monster_worm_count, tvbuf:range(pos, 1))
				local worm_count = tvbuf:range(pos, 1):uint()
				pos = pos + 1

				for _=1, worm_count do
					worm_tree:add(pf.monster_worm_len, tvbuf:range(pos, 1))
					local worm_len = tvbuf:range(pos, 1):uint()
					pos = pos + 1

					worm_tree:add(pf.monster_worm_string, tvbuf:range(pos, worm_len))
					pos = pos + worm_len
				end
				worm_tree.len = pos - worm_start_pos

				local rat_start_pos = pos
				local rat_tree = monster_tree:add(pf.monster_rat, tvbuf:range(pos))
				rat_tree:add(pf.monster_rat_count, tvbuf:range(pos, 1))
				local rat_count = tvbuf:range(pos, 1):uint()
				pos = pos + 1

				for _=1, rat_count do
					rat_tree:add(pf.monster_rat_len, tvbuf:range(pos, 1))
					local rat_len = tvbuf:range(pos, 1):uint()
					pos = pos + 1

					rat_tree:add(pf.monster_rat_string, tvbuf:range(pos, rat_len))
					pos = pos + rat_len
				end
				rat_tree.len = pos - rat_start_pos

				monster_tree:add_le(pf.monster_cat, tvbuf:range(pos, 2))
				pos = pos + 2

			else
				if pos + len > tvbuf:len() then
					pktinfo.cols.info:prepend("[Too short] ")
					tree:add_proto_expert_info(
						ef.too_short, "Packet too short for weird pebble data"
					)
					return pos, true
				end
				tree:add(pf["weird_pebble_"..id], tvbuf:range(pos, len))
				pos = pos + len
			end
		else
			pktinfo.cols.info:prepend("[Weird Unknown] ")
			tree:add_proto_expert_info(
				ef.unknown, "Unknown weird pebble id "..id
			)
			hit_unknown = true
			break
		end
	end

	return pos, hit_unknown
end

function dissect_gametick_pebbles(pos, tvbuf, pktinfo, tick_tree)
	local count_range = tvbuf:range(pos, 1)
	pos = pos + 1

	local count = count_range:le_uint()
	if count == 0xff then
		count_range = tvbuf:range(pos, 4)
		count = count_range:le_uint()
		pos = pos + 4
	end

	tick_tree:add_le(pf.gametick_pebble_count, count_range)

	for _=1, bit32.rshift(count, 1) do
		local id_range = tvbuf:range(pos, 1)
		tick_tree:add(pf.gametick_pebble_id, id_range)
		pos = pos + 1

		local id = id_range:uint()
		if gametick_pebbles[id] ~= nil then
			local info = gametick_pebbles[id]
			local len = info.len
			if id == 0x42 and tvbuf:range(pos, 1):uint() == 0xff then
				len = len + 2
			end

			if id == 0x6c then
				len = len + tvbuf:range(pos + 6, 1):uint() * 4
			end

			if id == 0x7e then
				len = len + tvbuf:range(pos + 5, 1):uint()
			end

			if id == 0x8f then
				local datalen = tvbuf:range(pos + 1, 1):uint()
				if datalen == 0xff then
					datalen = tvbuf:range(pos + 2, 4):le_uint() + 4
				end
				len = len + datalen + 12
			end

			if id == 0x98 then
				local datalen = tvbuf:range(pos + 5, 1):uint()
				if datalen == 0xff then
					datalen = tvbuf:range(pos + 6, 4):le_uint() + 4
				end
				len = len + datalen
			end

			tick_tree:add(pf["gametick_pebble_"..id], tvbuf:range(pos, len))
			pos = pos + len
		else
			pktinfo.cols.info:prepend("[Unknown pebble " .. id .. "] ")
			tick_tree:add_proto_expert_info(
				ef.unknown, "Unknown pebble id "..id
			)
			return pos, true
		end
	end

	if bit32.band(count, 0x01) == 0x01 then
		local odd_data = tick_tree:add(pf.gametick_odd, tvbuf:range(pos))
		local odd_data_start_pos = pos

		local count = tvbuf:range(pos, 1):uint()
		odd_data:add(pf.gametick_odd_count, tvbuf:range(pos, 1))
		pos = pos + 1

		for _=1, count do
			odd_data:add(pf.gametick_odd_id, tvbuf:range(pos, 1))
			pos = pos + 1

			odd_data:add_le(pf.gametick_odd_blue, tvbuf:range(pos, 4))
			pos = pos + 4

			local green_range, green_value
			pos, green_range, green_value = decode_uint16v(pos, tvbuf)
			odd_data:add(pf.gametick_odd_green, green_range, green_value)

			local tl_range, tl_value
			pos, tl_range, tl_value = decode_uint32v(pos, tvbuf)
			odd_data:add(pf.gametick_odd_total_length, tl_range, tl_value)

			local ss_range, ss_value
			pos, ss_range, ss_value = decode_uint32v(pos, tvbuf)
			odd_data:add(pf.gametick_odd_segment_start, ss_range, ss_value)

			local len_range, len_value
			pos, len_range, len_value = decode_uint32v(pos, tvbuf)
			odd_data:add(pf.gametick_odd_length, len_range, len_value)

			odd_data:add(pf.gametick_odd_payload, tvbuf:range(pos, len_value))
			pos = pos + len_value
		end

		odd_data.len = pos - odd_data_start_pos
	end

	return pos, false
end

function decode_uint32v(pos, tvbuf)
	local range = tvbuf:range(pos, 1)
	local value = range:le_uint()
	pos = pos + 1

	if value == 0xff then
		range = tvbuf:range(pos - 1, 5)
		value = tvbuf:range(pos, 4):le_uint()
		pos = pos + 4
	end

	return pos, range, value
end

function decode_uint16v(pos, tvbuf)
	local range = tvbuf:range(pos, 1)
	local value = range:le_uint()
	pos = pos + 1

	if value == 0xff then
		range = tvbuf:range(pos - 1, 3)
		value = tvbuf:range(pos, 2):le_uint()
		pos = pos + 2
	end

	return pos, range, value
end

DissectorTable.get("udp.port"):add(default_settings.port, fgp)
--XXX DEBUG
DissectorTable.get("udp.port"):add(5000, fgp) -- gridtest capture
DissectorTable.get("udp.port"):add(5002, fgp) -- gridtest capture
DissectorTable.get("udp.port"):add(34207, fgp) -- redmew capture
