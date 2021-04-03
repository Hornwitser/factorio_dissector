-- SPDX-License-Identifier: GPL-2.0-or-later
-- Factorio Game Protocol Dissector
--
-- Reverse engineered from packet captures and factorio.pdb
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
	broadcast = 34196,
	port = 34197,
}

-- Protocol fields
local pf = {}

-- Field extractors
local fe = {}

-- Expert info
local ef = {}
ef.too_short   = ProtoExpert.new("fgp.too_short.expert", "Factorio Game Protocol packet too short", expert.group.MALFORMED, expert.severity.ERROR)
ef.unknown     = ProtoExpert.new("fgp.unknown.expert", "Factorio Game Protocol unknown packet data", expert.group.UNDECODED, expert.severity.WARN)
ef.malformed   = ProtoExpert.new("fgp.malformed.expert", "Factorio Game Protocol malformed data", expert.group.MALFORMED, expert.severity.ERROR)
ef.unnecessary = ProtoExpert.new("fgp.unnecessary.expert", "Factorio Game PRotocol unnecessary encoding", expert.group.PROTOCOL, expert.severity.NOTE)


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

function decode_string(pos, tvbuf, tree, name, pf_name, show_value)
	local start_pos = pos
	local string_tree = tree:add(tvbuf:range(pos), name)

	local length_range, length
	pos, length_range, length = decode_uint32v(pos, tvbuf)
	string_tree:add(pf[pf_name .. "_length"], length_range, length)

	local data = tvbuf:range(pos, length):string()
	if show_value or show_value == nil then
		string_tree:append_text(": " .. data)
	end
	string_tree:add(pf[pf_name .. "_data"], tvbuf:range(pos, length))
	pos = pos + length
	string_tree.len = pos - start_pos

	return pos, data
end


local NetworkMessageType = {
	[0] = 'Ping',
	[1] = 'PingReply',
	[2] = 'ConnectionRequest',
	[3] = 'ConnectionRequestReply',
	[4] = 'ConnectionRequestReplyConfirm',
	[5] = 'ConnectionAcceptOrDeny',
	[6] = 'ClientToServerHeartbeat',
	[7] = 'ServerToClientHeartbeat',
	[8] = 'GetOwnAddress',
	[9] = 'GetOwnAddressReply',
	[10] = 'NatPunchRequest',
	[11] = 'NatPunch',
	[12] = 'TransferBlockRequest',
	[13] = 'TransferBlock',
	[14] = 'RequestForHeartbeatWhenDisconnecting',
	[15] = 'LANBroadcast',
	[16] = 'GameInformationRequest',
	[17] = 'GameInformationRequestReply',
	[18] = 'Empty',
}

local NetworkMessageTypeEnum = {}
for value, name in pairs(NetworkMessageType) do
	NetworkMessageTypeEnum[name] = value
end

-- For some weird reason connection requests include the
-- message id even though they don't have the fragmented flag set
always_has_message_id_types = {
	[NetworkMessageTypeEnum.ConnectionRequest] = true,
	[NetworkMessageTypeEnum.ConnectionRequestReplyConfirm] = true,
}


pf.flags = ProtoField.uint8("fgp.header.flags", "Flags", base.HEX, nil, 0, "NetworkHeader flags")

pf.message_type = ProtoField.uint8("fgp.header.type", "type", base.DEC, NetworkMessageType, 0x1f, "NetworkMessageType")
pf.random_flag  =  ProtoField.bool("fgp.header.random",        "random",       8,   nil, 0x20, "Checksum pertubation flag")
pf.fragmented   =  ProtoField.bool("fgp.header.fragmented",    "fragmented",   8,   nil, 0x40)
pf.last_frag    =  ProtoField.bool("fgp.header.last_fragment", "lastFragment", 8,   nil, 0x80)
pf.payload      = ProtoField.bytes("fgp.header.payload", "Payload", base.SPACE, "Message Data")

fe.message_type = "fgp.header.type"
fe.fragmented   = "fgp.header.fragmented"
fe.last_frag    = "fgp.header.last_fragment"

pf.message_id  = ProtoField.uint16("fgp.header.message_id", "Message ID",base.DEC, nil, 0x7fff, "Message ID fragment belongs to")
pf.confirm     =   ProtoField.bool("fgp.header.confirm", "confirm", 16, nil, 0x8000, "Contains Message ID confirmations")
pf.frag_number =  ProtoField.uint8("fgp.header.fragment_number", "fragmentNumber", base.DEC, nil, 0, "Fragment sequence number")
pf.frag_data   =  ProtoField.bytes("fgp.frag.data", "Fragment data", base.SPACE, "Fragment content")

fe.confirm     = "fgp.header.confirm"
fe.message_id  = "fgp.header.message_id"
fe.frag_number = "fgp.header.fragment_number"


pf.confirm_count = ProtoField.uint8("fgp.header.confirm_count", "Confirm count", base.DEC, nil, 0)
pf.confirm_item  = ProtoField.bytes("fgp.header.confirm_item", "Confirm Data", base.SPACE)


function dissect_network_message_header(pos, tvbuf, pktinfo, tree)
	local start_pos = pos
	local pktlen = tvbuf:reported_length_remaining()
	local header_tree = tree:add(tvbuf:range(pos, pktlen - pos), "NetworkMessageHeader")

	if pktlen < 1 then
		pktinfo.cols.info:set("[Malformed] Empty")
		header_tree:add_proto_expert_info(ef.too_short)
		return
	end

	local flagrange = tvbuf:range(pos, 1)
	pos = pos + 1
	local flag_tree = header_tree:add(pf.flags, flagrange)
	flag_tree:add(pf.message_type, flagrange)
	flag_tree:add(pf.random_flag, flagrange)
	flag_tree:add(pf.fragmented, flagrange)
	flag_tree:add(pf.last_frag, flagrange)

	pktinfo.cols.info:set(NetworkMessageType[fe.message_type()()] or "Unknown")

	local msg_type = fe.message_type()()
	local fragmented = fe.fragmented()()

	if fragmented or always_has_message_id_types[msg_type] then
		if pktlen < 4 then
			pktinfo.cols.info:append("[Too short] ")
			header_tree:add_proto_expert_info(
				ef.too_short, "Packet too short for fragment header"
			)

			return nil
		end

		header_tree:add_le(pf.message_id, tvbuf:range(pos, 2))
		header_tree:add_le(pf.confirm, tvbuf:range(pos, 2))
		pos = pos + 2

		if fragmented then
			header_tree:add(pf.frag_number, tvbuf:range(pos, 1))
			pos = pos + 1
		end

		if fe.confirm()() then
			header_tree:add(pf.confirm_count, tvbuf:range(pos, 1))
			local count = tvbuf:range(pos, 1):uint()
			pos = pos + 1

			for _=1, count do
				header_tree:add(pf.confirm_item, tvbuf:range(pos, 4))
				pos = pos + 4
			end
		end


	-- last frag set while fragment is unset
	elseif fe.last_frag()() then
		pktinfo.cols.info:prepend("[Unknown]")
		header_tree:add_proto_expert_info(
			ef.unknown, "Last Fragment flag set without Fragment flag"
		)
		return nil
	end

	header_tree.len = pos - start_pos
	header_tree:add(pf.payload, tvbuf:range(pos)):set_text("Payload (" .. pktlen - pos .. " bytes)")
	return pos
end


function dissect_network_message(pos, tvbuf, pktinfo, tree)
	local msg_type = fe.message_type()()
	local msg_tree = tree:add(tvbuf:range(pos), NetworkMessageType[msg_type] or "Unknown")

	-- Ping
	-- PingReply

	if msg_type == NetworkMessageTypeEnum.ConnectionRequest then
		pos = dissect_connection_request(pos, tvbuf, pktinfo, msg_tree)

	elseif msg_type == NetworkMessageTypeEnum.ConnectionRequestReply then
		pos = dissect_connection_request_reply(pos, tvbuf, pktinfo, msg_tree)

	elseif msg_type == NetworkMessageTypeEnum.ConnectionRequestReplyConfirm then
		pos = dissect_connection_request_reply_confirm(pos, tvbuf, pktinfo, msg_tree)

	elseif msg_type == NetworkMessageTypeEnum.ConnectionAcceptOrDeny then
		pos = dissect_connection_accept_or_deny(pos, tvbuf, pktinfo, msg_tree)

	elseif msg_type == NetworkMessageTypeEnum.ClientToServerHeartbeat then
		pos = dissect_heartbeat(pos, tvbuf, pktinfo, msg_tree, false)

	elseif msg_type == NetworkMessageTypeEnum.ServerToClientHeartbeat then
		pos = dissect_heartbeat(pos, tvbuf, pktinfo, msg_tree, true)

	-- GetOwnAddress
	-- GetOwnAddressReply
	-- NatPunchRequest
	-- NatPunch

	elseif msg_type == NetworkMessageTypeEnum.TransferBlockRequest then
		pos = dissect_transfer_block_request(pos, tvbuf, pktinfo, msg_tree)

	elseif msg_type == NetworkMessageTypeEnum.TransferBlock then
		pos = dissect_transfer_block(pos, tvbuf, pktinfo, msg_tree)

	-- RequestForHeartbeatWhenDisconnecting

	elseif msg_type == NetworkMessageTypeEnum.LANBroadcast then
		pos = dissect_lan_broadcast(pos, tvbuf, pktinfo, msg_tree)
	end

	-- GameInformationRequest -- Empty
	-- GameInformationRequestReply -- Likely the contents of ServerGameData
	-- Empty

	if pos ~= tvbuf:len() then
		local item = msg_tree:add(pf.unknown, tvbuf:range(pos, tvbuf:len() - pos))
		item:add_proto_expert_info(ef.unknown, "Undecoded data")
		pktinfo.cols.info:prepend("[Undecoded Data] ")
	end
end


pf.connection_request_major_ver = ProtoField.uint8("fgp.connection_request.version.major", "major", base.DEC, nil, 0)
pf.connection_request_minor_ver = ProtoField.uint8("fgp.connection_request.version.minor", "minor", base.DEC, nil, 0)
pf.connection_request_patch_ver = ProtoField.uint8("fgp.connection_request.version.patch", "patch", base.DEC, nil, 0)
pf.connection_request_build_ver = ProtoField.uint16("fgp.connection_request.version.build", "build", base.DEC, nil, 0)
pf.connection_request_client_id = ProtoField.uint32(
	"fgp.connection_request.connection_request_id_generated_on_client", "connectionRequestIDGeneratedOnClient", base.HEX, nil, 0
)

function dissect_connection_request(pos, tvbuf, pktinfo, tree)
	local version =
		tvbuf:range(pos, 1):uint() .. "." ..
		tvbuf:range(pos + 1, 1):uint() .. "." ..
		tvbuf:range(pos + 2, 1):uint() ..
		" (build " .. tvbuf:range(pos + 3, 2):le_uint() .. ")"

	local ver_tree = tree:add(tvbuf:range(pos, 5), "clientApplicationVersion: " .. version)
	ver_tree:add(pf.connection_request_major_ver, tvbuf:range(pos, 1))
	pos = pos + 1
	ver_tree:add(pf.connection_request_major_ver, tvbuf:range(pos, 1))
	pos = pos + 1
	ver_tree:add(pf.connection_request_major_ver, tvbuf:range(pos, 1))
	pos = pos + 1
	ver_tree:add_le(pf.connection_request_build_ver, tvbuf:range(pos, 2))
	pos = pos + 2

	tree:add_le(pf.connection_request_client_id, tvbuf:range(pos, 4))
	pos = pos + 4
	return pos
end

pf.connection_reply_major_ver = ProtoField.uint8("fgp.connection_request_reply.version.major", "major", base.DEC, nil, 0)
pf.connection_reply_minor_ver = ProtoField.uint8("fgp.connection_request_reply.version.minor", "minor", base.DEC, nil, 0)
pf.connection_reply_patch_ver = ProtoField.uint8("fgp.connection_request_reply.version.patch", "patch", base.DEC, nil, 0)
pf.connection_reply_build_ver = ProtoField.uint16("fgp.connection_request_reply.version.build", "build", base.DEC, nil, 0)
pf.connection_reply_client_id = ProtoField.uint32(
	"fgp.connection_request_reply.connection_request_id_generated_on_client", "connectionRequestIDGeneratedOnClient", base.HEX, nil, 0
)
pf.connection_reply_server_id = ProtoField.uint32(
	"fgp.connection_request_reply.connection_request_id_generated_on_server", "connectionRequestIDGeneratedOnServer", base.HEX, nil, 0
)

function dissect_connection_request_reply(pos, tvbuf, pktinf, tree)
	local version =
		tvbuf:range(pos, 1):uint() .. "." ..
		tvbuf:range(pos + 1, 1):uint() .. "." ..
		tvbuf:range(pos + 2, 1):uint() ..
		" (build " .. tvbuf:range(pos + 3, 2):le_uint() .. ")"

	local ver_tree = tree:add(tvbuf:range(pos, 5), "serverApplicationVersion: " .. version)
	ver_tree:add(pf.connection_reply_major_ver, tvbuf:range(pos, 1))
	pos = pos + 1
	ver_tree:add(pf.connection_reply_major_ver, tvbuf:range(pos, 1))
	pos = pos + 1
	ver_tree:add(pf.connection_reply_major_ver, tvbuf:range(pos, 1))
	pos = pos + 1
	ver_tree:add_le(pf.connection_reply_build_ver, tvbuf:range(pos, 2))
	pos = pos + 2

	tree:add_le(pf.connection_reply_client_id, tvbuf:range(pos, 4))
	pos = pos + 4

	tree:add_le(pf.connection_reply_server_id, tvbuf:range(pos, 4))
	pos = pos + 4
	return pos
end

-- ModID
pf.mod_id_name_length = ProtoField.uint32("fgp.mod_id.name.length", "length", base.DEC, nil, 0)
pf.mod_id_name_data = ProtoField.string("fgp.mod_id.name.data", "data", base.ASCII)
pf.mod_id_version_major = ProtoField.uint16("fgp.mod_id.version.major_version", "majorVersion", base.DEC, nil, 0)
pf.mod_id_version_minor = ProtoField.uint16("fgp.mod_id.version.minor_version", "minorVersion", base.DEC, nil, 0)
pf.mod_id_version_sub = ProtoField.uint16("fgp.mod_id.version.sub_version", "subVersion", base.DEC, nil, 0)
pf.mod_id_crc = ProtoField.uint32("fgp.mod_id.crc", "crc", base.DEC, nil, 0)

function dissect_mod_id(pos, tvbuf, pktinfo, tree)
	local start_pos = pos
	local mod_tree = tree:add(tvbuf:range(pos), "ModID")
	local name
	pos, name = decode_string(pos, tvbuf, mod_tree, "name", "mod_id_name")

	local ver_tree = mod_tree:add(tvbuf:range(pos), "version")
	local major_range, major_ver
	pos, major_range, major_ver = decode_uint16v(pos, tvbuf)
	ver_tree:add(pf.mod_id_version_major, major_range, major_ver)

	local minor_range, minor_ver
	pos, minor_range, minor_ver = decode_uint16v(pos, tvbuf)
	ver_tree:add(pf.mod_id_version_minor, minor_range, minor_ver)

	local sub_range, sub_ver
	pos, sub_range, sub_ver = decode_uint16v(pos, tvbuf)
	ver_tree:add(pf.mod_id_version_sub, sub_range, sub_ver)
	local version = major_ver .. "." .. minor_ver .. "." .. sub_ver
	ver_tree:append_text(": " .. version)

	mod_tree:add_le(pf.mod_id_crc, tvbuf:range(pos, 4))
	pos = pos + 4
	mod_tree.len = pos - start_pos

	mod_tree:append_text(": " .. name .. " " .. version)
	return pos
end

pf.connection_confirm_client_id = ProtoField.uint32(
	"fgp.connection_request_reply_confirm.connection_request_id_generated_on_client", "connectionRequestIDGeneratedOnClient", base.HEX, nil, 0
)
pf.connection_confirm_server_id = ProtoField.uint32(
	"fgp.connection_request_reply_confirm.connection_request_id_generated_on_server", "connectionRequestIDGeneratedOnServer", base.HEX, nil, 0
)
pf.connection_confirm_instance_id = ProtoField.uint32("fgp.connection_request_reply_confirm.instance_id", "instanceID", base.DEC, nil, 0)
pf.connection_confirm_username_length = ProtoField.uint32("fgp.connection_request_reply_confirm.username.length", "length", base.DEC, nil, 0)
pf.connection_confirm_username_data = ProtoField.string("fgp.connection_request_reply_confirm.username.data", "data", base.ASCII)
pf.connection_confirm_password_hash_length = ProtoField.uint32("fgp.connection_request_reply_confirm.password_hash.length", "length", base.DEC, nil, 0)
pf.connection_confirm_password_hash_data = ProtoField.string("fgp.connection_request_reply_confirm.password_hash.data", "data", base.ASCII)
pf.connection_confirm_server_key_length = ProtoField.uint32("fgp.connection_request_reply_confirm.server_key.length", "length", base.DEC, nil, 0)
pf.connection_confirm_server_key_data = ProtoField.string("fgp.connection_request_reply_confirm.server_key.data", "data", base.ASCII)
pf.connection_confirm_server_key_time_length = ProtoField.uint32("fgp.connection_request_reply_confirm.server_key_timestamp.length", "length", base.DEC, nil, 0)
pf.connection_confirm_server_key_time_data = ProtoField.string("fgp.connection_request_reply_confirm.server_key_timestamp.data", "data", base.ASCII)
pf.connection_confirm_core_checksum = ProtoField.uint32("fgp.connection_request_reply_confirm.core_checksum", "coreChecksum", base.DEC, nil, 0)
pf.connection_confirm_prototype_list_checksum = ProtoField.uint32("fgp.connection_request_reply_confirm.prototype_list_checksum", "prototypeListChecksum", base.DEC, nil, 0)
pf.connection_confirm_active_mods_size = ProtoField.uint32("fgp.connection_request_reply_confirm.active_mods.size", "size", base.DEC, nil, 0)


function dissect_connection_request_reply_confirm(pos, tvbuf, pktinf, tree)
	tree:add_le(pf.connection_confirm_client_id, tvbuf:range(pos, 4))
	pos = pos + 4
	tree:add_le(pf.connection_confirm_server_id, tvbuf:range(pos, 4))
	pos = pos + 4
	tree:add_le(pf.connection_confirm_instance_id, tvbuf:range(pos, 4))
	pos = pos + 4

	pos = decode_string(pos, tvbuf, tree, "username", "connection_confirm_username")
	pos = decode_string(pos, tvbuf, tree, "passwordHash", "connection_confirm_password_hash")
	pos = decode_string(pos, tvbuf, tree, "serverKey", "connection_confirm_server_key")
	pos = decode_string(pos, tvbuf, tree, "serverKeyTimestamp", "connection_confirm_server_key_time")

	tree:add_le(pf.connection_confirm_core_checksum, tvbuf:range(pos, 4))
	pos = pos + 4
	tree:add_le(pf.connection_confirm_prototype_list_checksum, tvbuf:range(pos, 4))
	pos = pos + 4

	local mods_size = tvbuf:range(pos, 1):uint()
	local mods_start_pos = pos
	local mods_tree = tree:add(tvbuf:range(pos), "activeMods")
	mods_tree:add(pf.connection_confirm_active_mods_size, tvbuf:range(pos, 1))
	pos = pos + 1

	for _=1, mods_size do
		pos = dissect_mod_id(pos, tvbuf, pktinfo, mods_tree)
	end
	mods_tree.len = pos - mods_start_pos

	-- TODO: startupModSettings

	return pos
end

-- ClientsPeerInfo
pf.clients_info_username_length = ProtoField.uint32("fgp.clients_peer_info.server_username.length", "length", base.DEC, nil, 0)
pf.clients_info_username_data = ProtoField.string("fgp.clients_peer_info.server_username.data", "data", base.ASCII)
pf.clients_info_map_saving_progress = ProtoField.uint8("fpg.clients_peer_info.map_saving_progress", "mapSavingProgress", base.DEC, nil, 0)
pf.clients_info_saving_for_size = ProtoField.uint8("fpg.clients_peer_info.saving_for.size", "size", base.DEC, nil, 0)
pf.clients_info_saving_for_item = ProtoField.uint16("fgp.clients_peer_info.saving_for.item", "item", base.DEC, nil, 0)
pf.clients_info_client_size = ProtoField.uint32("fpg.clients_peer_info.client_peer_info.size", "size", base.DEC, nil, 0)
pf.clients_info_client_first = ProtoField.uint16("fgp.clients_peer_info.client_peer_info.first", "first", base.DEC, nil, 0)

pf.clients_info_client_username_length = ProtoField.uint32("fgp.clients_peer_info.client_peer_info.username.length", "length", base.DEC, nil, 0)
pf.clients_info_client_username_data = ProtoField.string("fgp.clients_peer_info.client_peer_info.username.data", "data", base.ASCII)

pf.clients_info_client_flags = ProtoField.uint8("fgp.clients_peer_info.client_peer_info.flags", "flags", base.HEX, nil, 0)
pf.clients_info_client_bit0_flag = ProtoField.bool("fgp.clients_peer_info.client_peer_info.bit0_flag", "bit0", 8, nil, 0x01)
pf.clients_info_client_bit1_flag = ProtoField.bool("fgp.clients_peer_info.client_peer_info.bit1_flag", "bit1", 8, nil, 0x02)
pf.clients_info_client_bit2_flag = ProtoField.bool("fgp.clients_peer_info.client_peer_info.bit2_flag", "bit2", 8, nil, 0x04)
pf.clients_info_client_bit3_flag = ProtoField.bool("fgp.clients_peer_info.client_peer_info.bit3_flag", "bit3", 8, nil, 0x08)
pf.clients_info_client_bit4_flag = ProtoField.bool("fgp.clients_peer_info.client_peer_info.bit4_flag", "bit4", 8, nil, 0x10)
pf.clients_info_client_bit5_flag = ProtoField.bool("fgp.clients_peer_info.client_peer_info.bit5_flag", "bit5", 8, nil, 0x20)
pf.clients_info_client_bit6_flag = ProtoField.bool("fgp.clients_peer_info.client_peer_info.bit6_flag", "bit6", 8, nil, 0x40)
pf.clients_info_client_bit7_flag = ProtoField.bool("fgp.clients_peer_info.client_peer_info.bit7_flag", "bit7", 8, nil, 0x80)
-- These are the likely meanings of the flags
-- NON_DEFAULT_DROPPING_PROGRESS_VALUE -> droppingProgress
-- NON_DEFAULT_MAP_SAVING_PROGRESS_VALUE -> mapSavingProgress
-- NON_DEFAULT_MAP_DOWNLOADING_PROGRESS_VALUE -> mapDownloadingProgress
-- NON_DEFAULT_MAP_LOADING_PROGRESS_VALUE -> mapLoadingProgress
-- NON_DEFAULT_CATCHUP_PROGRESS_VALUE -> tryingToCatchUpProgress

pf.clients_info_client_progress = ProtoField.uint8("fpg.clients_peer_info.client_peer_info.progress_value", "progress", base.DEC, nil, 0)

function dissect_clients_peer_info(pos, tvbuf, pktinfo, tree)
	pos = decode_string(pos, tvbuf, tree, "serverUsername", "clients_info_username")

	tree:add(pf.clients_info_map_saving_progress, tvbuf:range(pos, 1))
	pos = pos + 1

	local saving_start_pos = pos
	local saving_size = tvbuf:range(pos, 1):uint()
	local saving_tree = tree:add(tvbuf:range(pos), "savingFor")
	saving_tree:add(pf.clients_info_saving_for_size, tvbuf:range(pos, 1))
	pos = pos + 1

	for _=1, saving_size do
		local item_range, item_value
		pos, item_range, item_value = decode_uint16v(pos, tvbuf)
		saving_tree:add(pf.clients_info_saving_for_item, item_range, item_value)
	end
	saving_tree.len = pos - saving_start_pos

	local client_start_pos = pos
	local client_tree = tree:add(tvbuf:range(pos), "clientPeerInfo")
	local client_size_range, client_size
	pos, client_size_range, client_size = decode_uint32v(pos, tvbuf)
	client_tree:add(pf.clients_info_client_size, client_size_range, client_size)

	for _=1, client_size do
		local entry_start_pos = pos
		local first_range, first_value
		pos, first_range, first_value = decode_uint16v(pos, tvbuf)
		local entry_tree = client_tree:add(tvbuf:range(pos), "entry: " .. first_value)
		entry_tree:add(pf.clients_info_client_first, first_range, first_value)

		pos = decode_string(pos, tvbuf, entry_tree, "username", "clients_info_client_username")

		local flags_range = tvbuf:range(pos, 1)
		local client_flags_tree = entry_tree:add(pf.clients_info_client_flags, flags_range)
		pos = pos + 1

		client_flags_tree:add(pf.clients_info_client_bit0_flag, flags_range)
		client_flags_tree:add(pf.clients_info_client_bit1_flag, flags_range)
		client_flags_tree:add(pf.clients_info_client_bit2_flag, flags_range)
		client_flags_tree:add(pf.clients_info_client_bit3_flag, flags_range)
		client_flags_tree:add(pf.clients_info_client_bit4_flag, flags_range)
		client_flags_tree:add(pf.clients_info_client_bit5_flag, flags_range)
		client_flags_tree:add(pf.clients_info_client_bit6_flag, flags_range)
		client_flags_tree:add(pf.clients_info_client_bit7_flag, flags_range)

		local flags_value = flags_range:uint()
		if bit32.band(flags_value, 0x01) ~= 0 then
			entry_tree:add(pf.clients_info_client_progress, tvbuf:range(pos, 1))
			pos = pos + 1
		end

		if bit32.band(flags_value, 0x02) ~= 0 then
			entry_tree:add(pf.clients_info_client_progress, tvbuf:range(pos, 1))
			pos = pos + 1
		end

		if bit32.band(flags_value, 0x04) ~= 0 then
			entry_tree:add(pf.clients_info_client_progress, tvbuf:range(pos, 1))
			pos = pos + 1
		end

		if bit32.band(flags_value, 0x08) ~= 0 then
			entry_tree:add(pf.clients_info_client_progress, tvbuf:range(pos, 1))
			pos = pos + 1
		end

		if bit32.band(flags_value, 0x10) ~= 0 then
			entry_tree:add(pf.clients_info_client_progress, tvbuf:range(pos, 1))
			pos = pos + 1
		end

		entry_tree.len = pos - entry_start_pos
	end
	client_tree.len = pos - client_start_pos
	return pos
end


local ConnectionRequestStatus = {
	[0] = 'Valid',
	[1] = 'ModsMismatch',
	[2] = 'CoreModMismatch',
	[3] = 'ModStartupSettingMismatch',
	[4] = 'PrototypeChecksumMismatch',
	[5] = 'PlayerLimitReached',
	[6] = 'PasswordMissing',
	[7] = 'PasswordMismatch',
	[8] = 'UserVerificationMissing',
	[9] = 'UserVerificationTimeout',
	[10] = 'UserVerificationMismatch',
	[11] = 'UserBanned',
	[12] = 'AddressUsedForDifferentPlayer',
	[13] = 'UserWithThatNameAlreadyInGame',
	[14] = 'UserNotWhitelisted',
}

pf.connection_accept_client_id = ProtoField.uint32(
	"fgp.connection_accept_or_deny.connection_request_id_generated_on_client", "connectionRequestIDGeneratedOnClient", base.HEX, nil, 0
)
pf.connection_accept_status = ProtoField.uint8("fpg.connection_accept_or_deny.status", "status", base.DEC, ConnectionRequestStatus, 0)
pf.connection_accept_game_name_length = ProtoField.uint32("fgp.connection_accept_or_deny.game_name.length", "length", base.DEC, nil, 0)
pf.connection_accept_game_name_data = ProtoField.string("fgp.connection_accept_or_deny.game_name.data", "data", base.ASCII)
pf.connection_accept_server_hash_length = ProtoField.uint32("fgp.connection_accept_or_deny.server_hash.length", "length", base.DEC, nil, 0)
pf.connection_accept_server_hash_data = ProtoField.string("fgp.connection_accept_or_deny.server_hash.data", "data", base.ASCII)
pf.connection_accept_description_length = ProtoField.uint32("fgp.connection_accept_or_deny.description.length", "length", base.DEC, nil, 0)
pf.connection_accept_description_data = ProtoField.string("fgp.connection_accept_or_deny.description.data", "data", base.ASCII)
pf.connection_accept_latency = ProtoField.uint8("fpg.connection_accept_or_deny.latency", "latency", base.DEC, nil, 0)
pf.connection_accept_game_id = ProtoField.uint32("fpg.connection_accept_or_deny.game_id", "gameID", base.DEC, nil, 0)
pf.connection_accept_steam_id = ProtoField.uint64("fpg.connection_accept_or_deny.steam_id", "steamID", base.DEC, nil, 0)
pf.connection_accept_expect_seq = ProtoField.uint32("fgp.connection_accept_or_deny.first_sequence_number_to_expect", "firstSequenceNumberToExpect", base.DEC, nil, 0)
pf.connection_accept_send_seq = ProtoField.uint32("fgp.connection_accept_or_deny.first_sequence_number_to_send", "firstSequenceNumberToSend", base.DEC, nil, 0)
pf.connection_accept_new_peer_id = ProtoField.uint16("fgp.connection_accept_or_deny.new_peer_id", "newPeerID", base.DEC, nil, 0)
pf.connection_accept_active_mods_size = ProtoField.uint32("fgp.connection_accept_or_deny.active_mods.size", "size", base.DEC, nil, 0)

function dissect_connection_accept_or_deny(pos, tvbuf, pktinf, tree)
	tree:add_le(pf.connection_accept_client_id, tvbuf:range(pos, 4))
	pos = pos + 4

	tree:add(pf.connection_accept_status, tvbuf:range(pos, 1))
	pos = pos + 1

	pos = decode_string(pos, tvbuf, tree, "gameName", "connection_accept_game_name")
	pos = decode_string(pos, tvbuf, tree, "serverHash", "connection_accept_server_hash")
	pos = decode_string(pos, tvbuf, tree, "description", "connection_accept_description")

	tree:add(pf.connection_accept_latency, tvbuf:range(pos, 1))
	pos = pos + 1

	tree:add_le(pf.connection_accept_game_id, tvbuf:range(pos, 4))
	pos = pos + 4

	tree:add_le(pf.connection_accept_steam_id, tvbuf:range(pos, 8))
	pos = pos + 8

	local peer_start = pos
	local peer_tree = tree:add(tvbuf:range(pos), "clientsPeerInfo")
	pos = dissect_clients_peer_info(pos, tvbuf, pktinfo, peer_tree)
	peer_tree.len = pos - peer_start

	tree:add_le(pf.connection_accept_expect_seq, tvbuf:range(pos, 4))
	pos = pos + 4

	tree:add_le(pf.connection_accept_send_seq, tvbuf:range(pos, 4))
	pos = pos + 4

	tree:add_le(pf.connection_accept_new_peer_id, tvbuf:range(pos, 2))
	pos = pos + 2

	local mods_size = tvbuf:range(pos, 1):uint()
	local mods_start_pos = pos
	local mods_tree = tree:add(tvbuf:range(pos), "activeMods")
	mods_tree:add(pf.connection_accept_active_mods_size, tvbuf:range(pos, 1))
	pos = pos + 1

	for _=1, mods_size do
		pos = dissect_mod_id(pos, tvbuf, pktinfo, mods_tree)
	end
	mods_tree.len = pos - mods_start_pos

	-- TODO: startupModSettings

	return pos
end

pf.heartbeat_flags = ProtoField.uint8("fgp.heartbeat.flags", "Flags", base.HEX, nil, 0)
pf.has_heartbeat_requests      = ProtoField.bool("fgp.heartbeat.has_heartbeat_requests",      "HAS_HEARTBEAT_REQUESTS",      8, nil, 0x01)
pf.has_tick_closures           = ProtoField.bool("fgp.heartbeat.has_tick_closures",           "HAS_TICK_CLOSURES",           8, nil, 0x02)
pf.has_single_tick_closure     = ProtoField.bool("fgp.heartbeat.has_single_tick_closure",     "HAS_SINGLE_TICK_CLOSURE",     8, nil, 0x04)
pf.all_tick_closures_are_empty = ProtoField.bool("fgp.heartbeat.all_tick_closures_are_empty", "ALL_TICK_CLOSURES_ARE_EMPTY", 8, nil, 0x08)
pf.has_synchronizer_action     = ProtoField.bool("fgp.heartbeat.has_synchronizer_action",     "HAS_SYNCHRONIZER_ACTION",     8, nil, 0x10)
pf.heartbeat_flag_bit5         = ProtoField.bool("fgp.heartbeat.flag_bit5",                   "Bit5",                        8, nil, 0x20)
pf.heartbeat_flag_bit6         = ProtoField.bool("fgp.heartbeat.flag_bit6",                   "Bit6",                        8, nil, 0x40)
pf.heartbeat_flag_bit7         = ProtoField.bool("fgp.heartbeat.flag_bit7",                   "Bit7",                        8, nil, 0x80)

fe.has_heartbeat_requests      = "fgp.heartbeat.has_heartbeat_requests"
fe.has_tick_closures           = "fgp.heartbeat.has_tick_closures"
fe.has_single_tick_closure     = "fgp.heartbeat.has_single_tick_closure"
fe.all_tick_closures_are_empty = "fgp.heartbeat.all_tick_closures_are_empty"
fe.has_synchronizer_action     = "fgp.heartbeat.has_synchronizer_action"

pf.heartbeat_sequence_number = ProtoField.uint32("fgp.heartbeat.sequence_number", "sequenceNumber", base.DEC, nil, 0)
pf.heartbeat_tick_closures_count = ProtoField.uint8("fgp.heartbeat.tick_closures.size", "size", base.DEC, nil, 0)

fe.heartbeat_sequence_number = "fgp.heartbeat.sequence_number"

pf.client_gametick_timeshift = ProtoField.uint32("fgp.client_gametick.timeshift", "nextToReceiveServerTickClosure",   base.DEC, nil, 0)
pf.heartbeat_synchronizer_actions_count = ProtoField.uint8("fgp.heartbeat.synchronizer_actions.size", "size", base.DEC, nil, 0)

pf.strange_size = ProtoField.uint8("fgp.heartbeat.request_for_heartbeat.size", "size", base.DEC, nil, 0)
pf.strange_data = ProtoField.uint32("fgp.heartbeat.request_for_heartbeat.item", "item", base.DEC, nil, 0)

function dissect_heartbeat(pos, tvbuf, pktinfo, tree, is_server)
	local pktlen = tvbuf:len()
	if pktlen < 1 then
		pktinfo.cols.info:prepend("[Too short] ")
		tree:add_proto_expert_info(ef.too_short)
		return pos
	end

	local heartbeat_flags_range = tvbuf:range(pos, 1)
	local heartbeat_flags_tree = tree:add(pf.heartbeat_flags, heartbeat_flags_range)
	pos = pos + 1

	heartbeat_flags_tree:add(pf.has_heartbeat_requests, heartbeat_flags_range)
	heartbeat_flags_tree:add(pf.has_tick_closures, heartbeat_flags_range)
	heartbeat_flags_tree:add(pf.has_single_tick_closure, heartbeat_flags_range)
	heartbeat_flags_tree:add(pf.all_tick_closures_are_empty, heartbeat_flags_range)
	heartbeat_flags_tree:add(pf.has_synchronizer_action, heartbeat_flags_range)
	heartbeat_flags_tree:add(pf.heartbeat_flag_bit5, heartbeat_flags_range)
	heartbeat_flags_tree:add(pf.heartbeat_flag_bit6, heartbeat_flags_range)
	heartbeat_flags_tree:add(pf.heartbeat_flag_bit7, heartbeat_flags_range)

	if pktlen < pos + 4 then
		pktinfo.cols.info:prepend("[Too short] ")
		tree:add_proto_expert_info(ef.too_short)
		return pos
	end

	tree:add_le(pf.heartbeat_sequence_number, tvbuf:range(pos, 4))
	pos = pos + 4
	pktinfo.cols.info:append(" Seq=" .. fe.heartbeat_sequence_number().display)

	local all_tick_closures_are_empty = fe.all_tick_closures_are_empty()()
	local tick_closures_count = nil

	local hit_unknown = false
	if fe.has_tick_closures()() then
		local tick_closures_start_pos = pos
		local tick_closures_tree = tree:add(tvbuf:range(pos), "tickClosures")

		if fe.has_single_tick_closure()() then
			tick_closures_count = 1
			local count_item = tick_closures_tree:add(pf.heartbeat_tick_closures_count, tick_closures_count)
			count_item.generated = true
		else
			tick_closures_count = tvbuf(pos, 1):uint()
			tick_closures_tree:add(pf.heartbeat_tick_closures_count, tvbuf(pos, 1))
			pos = pos + 1
		end

		for _=1, tick_closures_count do
			pos, hit_unknown = dissect_tick_closure(pos, tvbuf, pktinfo, tick_closures_tree, all_tick_closures_are_empty)

			if hit_unknown then
				break
			end
		end
		tick_closures_tree.len = pos - tick_closures_start_pos
	end

	if not hit_unknown and not is_server then
		tree:add_le(pf.client_gametick_timeshift, tvbuf:range(pos, 4))
		pos = pos + 4
	end

	if not hit_unknown and fe.has_synchronizer_action()() then
		local sync_tree_start_pos = pos
		local sync_tree = tree:add(tvbuf:range(pos), "synchronizerActions")

		local sync_count_range, sync_count
		pos, sync_count_range, sync_count = decode_uint32v(pos, tvbuf)
		sync_tree:add(pf.heartbeat_synchronizer_actions_count, sync_count_range, sync_count)

		for _=1, sync_count do
			pos, hit_unknown = dissect_synchronizer_action(pos, tvbuf, pktinfo, sync_tree, is_server)

			if hit_unknown then
				break
			end
		end
		sync_tree.len = pos - sync_tree_start_pos
	end

	if not hit_unknown and fe.has_heartbeat_requests()() then
		local req_count = tvbuf:range(pos, 1):uint()
		req_tree = tree:add(tvbuf:range(pos, 1 + req_count * 4), "requestsForHeartbeat: " .. req_count)
		req_tree:add(pf.strange_size, tvbuf:range(pos, 1))
		pos = pos + 1
		for _=1, req_count do
			req_tree:add_le(pf.strange_data, tvbuf:range(pos, 4))
			pos = pos + 4
		end
	end

	return pos
end



pf.tick_closure_update_tick   = ProtoField.uint32("fgp.tick_closure.update_tick",  "updateTick",   base.DEC, nil, 0)
pf.tick_closure_segments_size = ProtoField.uint8("fgp.tick_closure.input_action_segments.size", "size", base.DEC, nil, 0)

-- class TickClosure
function dissect_tick_closure(pos, tvbuf, pktinfo, tree, is_empty)
	local tick_tree = tree:add(tvbuf:range(pos), "TickClosure")
	local start_pos = pos

	tick_tree:add_le(pf.tick_closure_update_tick, tvbuf:range(pos, 4))
	pos = pos + 4

	local hit_unknown = false
	if not is_empty then
		local input_start_pos = pos
		local input_tree = tick_tree:add(tvbuf:range(pos), "inputActions")

		local count_range, count_flagged
		pos, count_range, count_flagged = decode_uint32v(pos, tvbuf)
		local count = bit32.rshift(count_flagged, 1)
		local has_segments = bit32.band(count_flagged, 1) == 1

		input_tree:add_le(pf.gametick_pebble_count, count_range, count)
		input_tree:append_text(": " .. count)

		for _=1, count do
			pos, hit_unknown = dissect_input_action(pos, tvbuf, pktinfo, input_tree)
			if hit_unknown then
				break
			end
		end
		input_tree.len = pos - input_start_pos

		if not hit_unknown and has_segments then
			local segment_start_pos = pos
			local segment_tree = tick_tree:add(tvbuf:range(pos), "inputActionSegments")

			local segment_count = tvbuf:range(pos, 1):uint()
			segment_tree:add(pf.tick_closure_segments_size, tvbuf:range(pos, 1))
			pos = pos + 1
			for _=1, segment_count do
				pos = dissect_input_action_segment(pos, tvbuf, pktinfo, segment_tree)
			end
			segment_tree.len = pos - segment_start_pos
		end
	end

	tick_tree.len = pos - start_pos
	return pos, hit_unknown
end


input_actions = {}
input_actions[0x00] = {
	name = 'Nothing',
}

input_actions[0x01] = {
	name = 'StopWalking',
	len = 1,
}

input_actions[0x02] = {
	name = 'BeginMining',
	len = 1,
}

input_actions[0x03] = {
	name = 'StopMining',
	len = 1,
}

input_actions[0x04] = {
	name = 'ToggleDriving',
	len = 1,
}

input_actions[0x05] = {
	name = 'OpenGui',
	len = 1,
}

input_actions[0x06] = {
	name = 'CloseGui',
	len = 1,
}

input_actions[0x07] = {
	name = 'OpenCharacterGui',
	len = 1,
}

input_actions[0x08] = {
	name = 'OpenCurrentVehicleGui',
	len = 1,
}

input_actions[0x09] = {
	name = 'ConnectRollingStock',
	len = 1,
}

input_actions[0x0a] = {
	name = 'DisconnectRollingStock',
	len = 1,
}

input_actions[0x0b] = {
	name = 'SelectedEntityCleared',
	len = 1,
}

input_actions[0x0c] = {
	name = 'ClearCursor',
	len = 1,
}

input_actions[0x0d] = {
	name = 'ResetAssemblingMachine',
	len = 1,
}

input_actions[0x0e] = {
	name = 'OpenTechnologyGui',
}

input_actions[0x0f] = {
	name = 'LaunchRocket',
	len = 1,
}

input_actions[0x10] = {
	name = 'OpenProductionGui',
	len = 1,
}

input_actions[0x11] = {
	name = 'StopRepair',
	len = 1,
}

input_actions[0x12] = {
	name = 'CancelNewBlueprint',
	len = 1,
}

input_actions[0x13] = {
	name = 'CloseBlueprintRecord',
	len = 1,
}

input_actions[0x14] = {
	name = 'CopyEntitySettings',
	len = 1,
}

input_actions[0x15] = {
	name = 'PasteEntitySettings',
	len = 1,
}

input_actions[0x16] = {
	name = 'DestroyOpenedItem',
	len = 1,
}

input_actions[0x17] = {
	name = 'CopyOpenedItem',
	len = 1,
}

input_actions[0x18] = {
	name = 'ToggleShowEntityInfo',
}

input_actions[0x19] = {
	name = 'SingleplayerInit',
	len = 1,
}

input_actions[0x1a] = {
	name = 'MultiplayerInit',
}

input_actions[0x1b] = {
	name = 'DisconnectAllPlayers',
	len = 1,
}

input_actions[0x1c] = {
	name = 'SwitchToRenameStopGui',
	len = 1,
}

input_actions[0x1d] = {
	name = 'OpenBonusGui',
	len = 1,
}

input_actions[0x1e] = {
	name = 'OpenTrainsGui',
	len = 1,
}

input_actions[0x1f] = {
	name = 'OpenAchievementsGui',
	len = 1,
}

input_actions[0x20] = {
	name = 'CycleBlueprintBookForwards',
	len = 1,
}

input_actions[0x21] = {
	name = 'CycleBlueprintBookBackwards',
}

input_actions[0x22] = {
	name = 'CycleClipboardForwards',
}

input_actions[0x23] = {
	name = 'CycleClipboardBackwards',
}

input_actions[0x24] = {
	name = 'StopMovementInTheNextTick',
	len = 1,
}

input_actions[0x25] = {
	name = 'ToggleEnableVehicleLogisticsWhileMoving',
	len = 1,
}

input_actions[0x26] = {
	name = 'ToggleDeconstructionItemEntityFilterMode',
}

input_actions[0x27] = {
	name = 'ToggleDeconstructionItemTileFilterMode',
}

input_actions[0x28] = {
	name = 'OpenLogisticGui',
}

input_actions[0x29] = {
	name = 'SelectNextValidGun',
	len = 1,
}

input_actions[0x2a] = {
	name = 'ToggleMapEditor',
	len = 1,
}

input_actions[0x2b] = {
	name = 'DeleteBlueprintLibrary',
	len = 1,
}

input_actions[0x2c] = {
	name = 'GameCreatedFromScenario',
}

input_actions[0x2d] = {
	name = 'ActivateCopy',
}

input_actions[0x2e] = {
	name = 'ActivateCut',
}

input_actions[0x2f] = {
	name = 'ActivatePaste',
	len = 1,
}

input_actions[0x30] = {
	name = 'Undo',
}

input_actions[0x31] = {
	name = 'TogglePersonalRoboport',
	len = 1,
}

input_actions[0x32] = {
	name = 'ToggleEquipmentMovementBonus',
}

input_actions[0x33] = {
	name = 'TogglePersonalLogisticRequests',
}

input_actions[0x34] = {
	name = 'ToggleEntityLogisticRequests',
}

input_actions[0x35] = {
	name = 'StopBuildingByMoving',
	len = 1,
}

input_actions[0x36] = {
	name = 'FlushOpenedEntityFluid',
	len = 9,
}

input_actions[0x37] = {
	name = 'OpenTipsAndTricksGui',
	len = 14,
}

input_actions[0x38] = {
	name = 'OpenBlueprintLibraryGui',
	len = 2,
}

input_actions[0x39] = {
	name = 'ChangeBlueprintLibraryTab',
	len = 9,
}

input_actions[0x3a] = {
	name = 'DropItem',
	len = 3,
}

input_actions[0x3b] = {
	name = 'Build',
	len = 6
}

input_actions[0x3c] = {
	name = 'StartWalking',
}

input_actions[0x3d] = {
	name = 'BeginMiningTerrain',
}

input_actions[0x3e] = {
	name = 'ChangeRidingState',
	len = 6
}

input_actions[0x3f] = {
	name = 'OpenItem',
	len = 6
}

input_actions[0x40] = {
	name = 'OpenParentOfOpenedItem',
	len = 6
}

input_actions[0x41] = {
	name = 'ResetItem',
	len = 6
}

input_actions[0x42] = {
	name = 'DestroyItem',
	len = 9
}

input_actions[0x43] = {
	name = 'OpenModItem',
	len = 7,
}

input_actions[0x44] = {
	name = 'OpenEquipment',
}

input_actions[0x45] = {
	name = 'CursorTransfer',
	len = 10,
}

input_actions[0x46] = {
	name = 'CursorSplit',
	len = 3,
}

input_actions[0x47] = {
	name = 'StackTransfer',
	len = 6,
}

input_actions[0x48] = {
	name = 'InventoryTransfer',
	len = 5,
}

-- ActionData::CrcData
pf.crc_data_crc         = ProtoField.uint32("fgp.input_action.crc_data.crc", "crc", base.DEC, nil, 0)
pf.crc_data_tick_of_crc = ProtoField.uint32("fgp.input_action.crc_data.tick_of_crc", "tickOfCrc",base.DEC, nil, 0)

input_actions[0x49] = {
	name = 'CheckCRCHeuristic',
	dissect = function(pos, tvbuf, pktinfo, tree)
		pos, range, value = decode_uint16v(pos, tvbuf)
		tree:add(range, value, "Unknown")

		tree:add_le(pf.crc_data_crc, tvbuf:range(pos, 4))
		pos = pos + 4
		tree:add_le(pf.crc_data_tick_of_crc, tvbuf:range(pos, 4))
		pos = pos + 4

		return pos
	end
}

input_actions[0x4a] = {
	name = 'Craft',
	len = 6,
}

input_actions[0x4b] = {
	name = 'WireDragging',
	len = 5,
}

input_actions[0x4c] = {
	name = 'ChangeShootingState',
	len = 8,
}

input_actions[0x4d] = {
	name = 'SetupAssemblingMachine',
}

input_actions[0x4e] = {
	name = 'SelectedEntityChanged',
}

input_actions[0x4f] = {
	name = 'SmartPipette',
}

input_actions[0x50] = {
	name = 'StackSplit',
	len = 3,
}

input_actions[0x51] = {
	name = 'InventorySplit',
	len = 9
}

input_actions[0x52] = {
	name = 'CancelCraft',
}

input_actions[0x53] = {
	name = 'SetFilter',
}

input_actions[0x54] = {
	name = 'CheckCRC',
	len = 10,
}

input_actions[0x55] = {
	name = 'SetCircuitCondition',
}

input_actions[0x56] = {
	name = 'SetSignal',
}

input_actions[0x57] = {
	name = 'StartResearch',
}

input_actions[0x58] = {
	name = 'SetLogisticFilterItem',
}

input_actions[0x59] = {
	name = 'SetLogisticFilterSignal',
	len = 2,
}

input_actions[0x5a] = {
	name = 'SetCircuitModeOfOperation',
	len = 13,
}

input_actions[0x5b] = {
	name = 'GuiClick',
}

input_actions[0x5c] = {
	name = 'GuiConfirmed',
}

input_actions[0x5d] = {
	name = 'WriteToConsole',
	len = 18,
}

input_actions[0x5e] = {
	name = 'MarketOffer',
	len = 10,
}

input_actions[0x5f] = {
	name = 'AddTrainStation',
	len = 10,
}

input_actions[0x60] = {
	name = 'ChangeTrainStopStation',
	len = 9,
}

input_actions[0x61] = {
	name = 'ChangeActiveItemGroupForCrafting',
	len = 26,
}

input_actions[0x62] = {
	name = 'ChangeActiveItemGroupForFilters',
	len = 6,
}

input_actions[0x63] = {
	name = 'ChangeActiveCharacterTab',
	len = 2,
}

input_actions[0x64] = {
	name = 'GuiTextChanged',
}

input_actions[0x65] = {
	name = 'GuiCheckedStateChanged',
	len = 9,
}

input_actions[0x66] = {
	name = 'GuiSelectionStateChanged',
}

input_actions[0x67] = {
	name = 'GuiSelectedTabChanged',
}

input_actions[0x68] = {
	name = 'GuiValueChanged',
	len = 24,
}

input_actions[0x69] = {
	name = 'GuiSwitchStateChanged',
}

input_actions[0x6a] = {
	name = 'GuiLocationChanged',
	len = 24,
}

input_actions[0x6b] = {
	name = 'PlaceEquipment',
}

input_actions[0x6c] = {
	name = 'TakeEquipment',
	len = 16, -- Variable length
}

input_actions[0x6d] = {
	name = 'UseItem',
}

input_actions[0x6e] = {
	name = 'SendSpidertron',
}

input_actions[0x6f] = {
	name = 'UseArtilleryRemote',
	len = 7,
}

input_actions[0x70] = {
	name = 'SetInventoryBar',
	len = 7,
}

input_actions[0x71] = {
	name = 'MoveOnZoom',
}

input_actions[0x72] = {
	name = 'StartRepair',
	len = 7,
}

input_actions[0x73] = {
	name = 'Deconstruct',
	len = 9,
}

input_actions[0x74] = {
	name = 'Upgrade',
}

input_actions[0x75] = {
	name = 'Copy',
	len = 3,
}

input_actions[0x76] = {
	name = 'AlternativeCopy',
}

input_actions[0x77] = {
	name = 'SelectBlueprintEntities',
}

input_actions[0x78] = {
	name = 'AltSelectBlueprintEntities',
}

input_actions[0x79] = {
	name = 'SetupBlueprint',
}

input_actions[0x7a] = {
	name = 'SetupSingleBlueprintRecord',
}

input_actions[0x7b] = {
	name = 'CopyOpenedBlueprint',
}

input_actions[0x7c] = {
	name = 'ReassignBlueprint',
}

input_actions[0x7d] = {
	name = 'OpenBlueprintRecord',
}

input_actions[0x7e] = {
	name = 'GrabBlueprintRecord',
	len = 8,
}

input_actions[0x7f] = {
	name = 'DropBlueprintRecord',
}

input_actions[0x80] = {
	name = 'DeleteBlueprintRecord',
}

input_actions[0x81] = {
	name = 'UpgradeOpenedBlueprintByRecord',
}

input_actions[0x82] = {
	name = 'UpgradeOpenedBlueprintByItem',
}

input_actions[0x83] = {
	name = 'SpawnItem',
}

input_actions[0x84] = {
	name = 'SpawnItemStackTransfer',
}

input_actions[0x85] = {
	name = 'UpdateBlueprintShelf',
}

input_actions[0x86] = {
	name = 'TransferBlueprint',
	len = 14,
}

input_actions[0x87] = {
	name = 'TransferBlueprintImmediately',
	len = 11,
}

input_actions[0x88] = {
	name = 'EditBlueprintToolPreview',
}

input_actions[0x89] = {
	name = 'RemoveCables',
}

input_actions[0x8a] = {
	name = 'ExportBlueprint',
}

input_actions[0x8b] = {
	name = 'ImportBlueprint',
	len = 17,
}

input_actions[0x8c] = {
	name = 'ImportBlueprintsFiltered',
	len = 7,
}

input_actions[0x8d] = {
	name = 'PlayerJoinGame',
	len = 8, -- variable length
}

input_actions[0x8e] = {
	name = 'PlayerAdminChange',
}

input_actions[0x8f] = {
	name = 'CancelDeconstruct',
	len = 2,
}

input_actions[0x90] = {
	name = 'CancelUpgrade',
	len = 6,
}

input_actions[0x91] = {
	name = 'ChangeArithmeticCombinatorParameters',
}

input_actions[0x92] = {
	name = 'ChangeDeciderCombinatorParameters',
}

input_actions[0x93] = {
	name = 'ChangeProgrammableSpeakerParameters',
}

input_actions[0x94] = {
	name = 'ChangeProgrammableSpeakerAlertParameters',
}

input_actions[0x95] = {
	name = 'ChangeProgrammableSpeakerCircuitParameters',
}

input_actions[0x96] = {
	name = 'SetVehicleAutomaticTargetingParameters',
}

input_actions[0x97] = {
	name = 'BuildTerrain',
}

input_actions[0x98] = {
	name = 'ChangeTrainWaitCondition',
	len = 17,
}

input_actions[0x99] = {
	name = 'ChangeTrainWaitConditionData',
}

input_actions[0x9a] = {
	name = 'CustomInput',
}

input_actions[0x9b] = {
	name = 'ChangeItemLabel',
}

input_actions[0x9c] = {
	name = 'ChangeItemDescription',
}

input_actions[0x9d] = {
	name = 'ChangeEntityLabel',
}

input_actions[0x9e] = {
	name = 'BuildRail',
}

input_actions[0x9f] = {
	name = 'CancelResearch',
	len = 13,
}

input_actions[0xa0] = {
	name = 'SelectArea',
}

input_actions[0xa1] = {
	name = 'AltSelectArea',
}

input_actions[0xa2] = {
	name = 'ServerCommand',
	len = 5,
}

input_actions[0xa3] = {
	name = 'SetControllerLogisticTrashFilterItem',
}

input_actions[0xa4] = {
	name = 'SetEntityLogisticTrashFilterItem',
}

input_actions[0xa5] = {
	name = 'SetInfinityContainerFilterItem',
}

input_actions[0xa6] = {
	name = 'SetInfinityPipeFilter',
	len = 9,
}

input_actions[0xa7] = {
	name = 'ModSettingsChanged',
	len = 8,
}

input_actions[0xa8] = {
	name = 'SetEntityEnergyProperty',
	len = 5,
}

input_actions[0xa9] = {
	name = 'EditCustomTag',
	len = 3,
}

input_actions[0xaa] = {
	name = 'EditPermissionGroup',
	len = 2,
}

input_actions[0xab] = {
	name = 'ImportBlueprintString',
}

input_actions[0xac] = {
	name = 'ImportPermissionsString',
}

input_actions[0xad] = {
	name = 'ReloadScript',
}

input_actions[0xae] = {
	name = 'ReloadScriptDataTooLarge',
}

input_actions[0xaf] = {
	name = 'GuiElemChanged',
}

input_actions[0xb0] = {
	name = 'BlueprintTransferQueueUpdate',
	len = 2,
}

input_actions[0xb1] = {
	name = 'DragTrainSchedule',
	len = 2,
}

input_actions[0xb2] = {
	name = 'DragTrainWaitCondition',
	len = 3,
}

input_actions[0xb3] = {
	name = 'SelectItem',
	len = 5,
}

input_actions[0xb4] = {
	name = 'SelectEntitySlot',
	len = 5,
}

input_actions[0xb5] = {
	name = 'SelectTileSlot',
}

input_actions[0xb6] = {
	name = 'SelectMapperSlot',
}

input_actions[0xb7] = {
	name = 'DisplayResolutionChanged',
}

input_actions[0xb8] = {
	name = 'QuickBarSetSlot',
}

input_actions[0xb9] = {
	name = 'QuickBarPickSlot',
}

input_actions[0xba] = {
	name = 'QuickBarSetSelectedPage',
}

input_actions[0xbb] = {
	name = 'PlayerLeaveGame',
	len = 2,
}

input_actions[0xbc] = {
	name = 'MapEditorAction',
	len = 2,
}

input_actions[0xbd] = {
	name = 'PutSpecialItemInMap',
	len = 2,
}

input_actions[0xbe] = {
	name = 'PutSpecialRecordInMap',
	len = 2,
}

input_actions[0xbf] = {
	name = 'ChangeMultiplayerConfig',
	len = 2,
}

input_actions[0xc0] = {
	name = 'AdminAction',
}

input_actions[0xc1] = {
	name = 'LuaShortcut',
}

input_actions[0xc2] = {
	name = 'TranslateString',
}

input_actions[0xc3] = {
	name = 'FlushOpenedEntitySpecificFluid',
}

input_actions[0xc4] = {
	name = 'ChangePickingState',
}

input_actions[0xc5] = {
	name = 'SelectedEntityChangedVeryClose',
	len = 2,
}

input_actions[0xc6] = {
	name = 'SelectedEntityChangedVeryClosePrecise',
}

input_actions[0xc7] = {
	name = 'SelectedEntityChangedRelative',
	len = 5,
}

input_actions[0xc8] = {
	name = 'SelectedEntityChangedBasedOnUnitNumber',
}

input_actions[0xc9] = {
	name = 'SetAutosortInventory',
}

input_actions[0xca] = {
	name = 'SetFlatControllerGui',
}

input_actions[0xcb] = {
	name = 'SetRecipeNotifications',
}

input_actions[0xcc] = {
	name = 'SetAutoLaunchRocket',
}

input_actions[0xcd] = {
	name = 'SwitchConstantCombinatorState',
}

input_actions[0xce] = {
	name = 'SwitchPowerSwitchState',
	len = 9,
}

input_actions[0xcf] = {
	name = 'SwitchInserterFilterModeState',
	len = 2,
}

input_actions[0xd0] = {
	name = 'SwitchConnectToLogisticNetwork',
}

input_actions[0xd1] = {
	name = 'SetBehaviorMode',
	len = 9,
}

input_actions[0xd2] = {
	name = 'FastEntityTransfer',
	len = 2,
}

input_actions[0xd3] = {
	name = 'RotateEntity',
}

input_actions[0xd4] = {
	name = 'FastEntitySplit',
}

input_actions[0xd5] = {
	name = 'SetTrainStopped',
}

input_actions[0xd6] = {
	name = 'ChangeControllerSpeed',
}

input_actions[0xd7] = {
	name = 'SetAllowCommands',
}

input_actions[0xd8] = {
	name = 'SetResearchFinishedStopsGame',
}

input_actions[0xd9] = {
	name = 'SetInserterMaxStackSize',
	len = 2,
}

input_actions[0xda] = {
	name = 'OpenTrainGui',
}

input_actions[0xdb] = {
	name = 'SetEntityColor',
}

input_actions[0xdc] = {
	name = 'SetDeconstructionItemTreesAndRocksOnly',
}

input_actions[0xdd] = {
	name = 'SetDeconstructionItemTileSelectionMode',
}

input_actions[0xde] = {
	name = 'DeleteCustomTag',
}

input_actions[0xdf] = {
	name = 'DeletePermissionGroup',
}

input_actions[0xe0] = {
	name = 'AddPermissionGroup',
}

input_actions[0xe1] = {
	name = 'SetInfinityContainerRemoveUnfilteredItems',
}

input_actions[0xe2] = {
	name = 'SetCarWeaponsControl',
}

input_actions[0xe3] = {
	name = 'SetRequestFromBuffers',
}

input_actions[0xe4] = {
	name = 'ChangeActiveQuickBar',
}

input_actions[0xe5] = {
	name = 'OpenPermissionsGui',
}

input_actions[0xe6] = {
	name = 'DisplayScaleChanged',
}

input_actions[0xe7] = {
	name = 'SetSplitterPriority',
}

input_actions[0xe8] = {
	name = 'GrabInternalBlueprintFromText',
}

input_actions[0xe9] = {
	name = 'SetHeatInterfaceTemperature',
}

input_actions[0xea] = {
	name = 'SetHeatInterfaceMode',
}

input_actions[0xeb] = {
	name = 'OpenTrainStationGui',
}

input_actions[0xec] = {
	name = 'RemoveTrainStation',
}

input_actions[0xed] = {
	name = 'GoToTrainStation',
}

input_actions[0xee] = {
	name = 'RenderModeChanged',
}

input_actions[0xef] = {
	name = 'SetPlayerColor',
}

input_actions[0xf0] = {
	name = 'PlayerClickedGpsTag',
}

input_actions[0xf1] = {
	name = 'SetTrainsLimit',
}

input_actions[0xf2] = {
	name = 'ClearRecipeNotification',
}

input_actions[0xf3] = {
	name = 'SetLinkedContainerLinkID',
}

local InputActionType = {}
local InputActionTypeEnum = {}
for id, data in pairs(input_actions) do
	InputActionType[id] = data.name
	InputActionTypeEnum[data.name] = id
end

pf.gametick_pebble_count = ProtoField.uint8("fgp.tick_closure.input_actions.size", "size", base.DEC, nil, 0)
pf.gametick_pebble_id    = ProtoField.uint8("fgp.input_action.type", "type", base.HEX, InputActionType, 0)
pf.gametick_pebble_data = ProtoField.bytes("fgp.input_action.data", "data", base.SPACE, desc)


function dissect_input_action(pos, tvbuf, pktinfo, tree)
	local input_start_pos = pos
	local input_type = tvbuf:range(pos, 1):uint()
	local input_tree = tree:add(tvbuf:range(pos), "InputAction")
	input_tree:add(pf.gametick_pebble_id, tvbuf:range(pos, 1))
	pos = pos + 1

	local info = input_actions[input_type]
	if info ~= nil then
		input_tree:set_text(info.name)
		if info.dissect then
			pos = info.dissect(pos, tvbuf, pktinfo, input_tree)

		elseif info.len then
			local len = info.len
			if input_type == 0x6c then
				len = len + tvbuf:range(pos + 6, 1):uint() * 4
			end

			if input_type == 0x7e then
				len = len + tvbuf:range(pos + 5, 1):uint()
			end

			if input_type == 0x8d then
				len = len + tvbuf:range(pos + 5, 1):uint()
			end

			if input_type == 0x8f then
				local datalen = tvbuf:range(pos + 1, 1):uint()
				if datalen == 0xff then
					datalen = tvbuf:range(pos + 2, 4):le_uint() + 4
				end
				len = len + datalen + 12
			end

			if input_type == 0x98 then
				local datalen = tvbuf:range(pos + 5, 1):uint()
				if datalen == 0xff then
					datalen = tvbuf:range(pos + 6, 4):le_uint() + 4
				end
				len = len + datalen
			end

			input_tree:add(pf.gametick_pebble_data, tvbuf:range(pos, len))
			pos = pos + len

		else
			pktinfo.cols.info:prepend("[Input #" .. input_type .. " len unknown] ")
			input_tree:add_proto_expert_info(
				ef.unknown, "Unknown length for " .. InputActionTypeEnum[input_type]
			)
			return pos, true

		end

	else
		pktinfo.cols.info:prepend("[Input #" .. input_type .. " unknown] ")
		input_tree:add_proto_expert_info(
			ef.unknown, "Unknown InputActionType " .. input_type
		)
		return pos, true
	end
	input_tree.len = pos - input_start_pos

	return pos, false
end



pf.input_action_segment_id            = ProtoField.uint8("fgp.input_action_segment.type", "type", base.HEX, InputActionType, 0)
pf.input_action_segment_blue          = ProtoField.uint32("fgp.input_action_segment.id", "id", base.HEX, nil, 0)
pf.input_action_segment_green         = ProtoField.uint16("fgp.input_action_segment.player_index", "playerIndex", base.DEC, nil, 0)
pf.input_action_segment_total_length  = ProtoField.uint32("fgp.input_action_segment.total_segments", "totalSegments", base.DEC, nil, 0)
pf.input_action_segment_segment_start = ProtoField.uint32("fgp.input_action_segment.segment_number", "segmentNumber", base.DEC, nil, 0)
pf.input_action_segment_payload_length = ProtoField.uint32("fgp.input_action_segment.payload.length", "length", base.DEC, nil, 0)
pf.input_action_segment_payload_data   = ProtoField.bytes("fgp.input_action_segment.payload.data", "data", base.SPACE)

function dissect_input_action_segment(pos, tvbuf, pktinfo, tree)
	local segment_start_pos = pos
	local segment_type = tvbuf:range(pos, 1):uint()
	local hex_type = string.format("0x%02x", segment_type)
	local segment_tree = tree:add(
		tvbuf:range(pos),
		"InputActionSegment: " .. (InputActionType[segment_type] or "Unknown") .. " (" .. hex_type .. ")"
	)

	segment_tree:add(pf.input_action_segment_id, tvbuf:range(pos, 1))
	pos = pos + 1

	segment_tree:add_le(pf.input_action_segment_blue, tvbuf:range(pos, 4))
	pos = pos + 4

	local green_range, green_value
	pos, green_range, green_value = decode_uint16v(pos, tvbuf)
	segment_tree:add(pf.input_action_segment_green, green_range, green_value)

	local tl_range, tl_value
	pos, tl_range, tl_value = decode_uint32v(pos, tvbuf)
	segment_tree:add(pf.input_action_segment_total_length, tl_range, tl_value)

	local ss_range, ss_value
	pos, ss_range, ss_value = decode_uint32v(pos, tvbuf)
	segment_tree:add(pf.input_action_segment_segment_start, ss_range, ss_value)

	pos = decode_string(pos, tvbuf, segment_tree, "payload", "input_action_segment_payload", false)

	segment_tree.len = pos - segment_start_pos
	return pos, false
end



pf.synchronizer_action_peer_id = ProtoField.uint16("fgp.synchronizer_action.sender_peer_id", "senderPeerId", base.DEC, nil, 0)

synchronizer_actions = {}
synchronizer_actions[0x00] = {
	name = 'GameEnd',
	len = 0,
}

synchronizer_actions[0x01] = {
	name = 'PeerDisconnect',
	len = 1,
}

pf.new_peer_info_username_length = ProtoField.uint8("fgp.new_peer_info.username.length", "length", base.DEC, nil, 0)
pf.new_peer_info_username_data = ProtoField.string("fgp.new_peer_info.username.data", "data", base.ASCII)

synchronizer_actions[0x02] = {
	name = 'NewPeerInfo',
	dissect = function(pos, tvbuf, pktinfo, tree, is_server)
		pos = decode_string(pos, tvbuf, tree, "username", "new_peer_info_username")

		return pos, false
	end,
}

ClientMultiplayerStateType = {
	[0] = 'Ready',
	[1] = 'Connecting',
	[2] = 'ConnectedWaitingForMap',
	[3] = 'ConnectedDownloadingMap',
	[4] = 'ConnectedLoadingMap',
	[5] = 'TryingToCatchUp',
	[6] = 'WaitingForCommandToStartSendingTickClosures',
	[7] = 'InGame',
	[8] = 'DisconnectScheduled',
	[9] = 'WaitingForDisconnectConfirmation',
	[10] = 'WaitingForUserToSaveOrQuitAfterServerLeft',
	[11] = 'Disconnected',
	[12] = 'Failed',
	[13] = 'InitializationFailed',
	[14] = 'DesyncedWaitingForMap',
	[15] = 'DesyncedCatchingUpWithMapReadyForDownload',
	[16] = 'DesyncedSavingLocalVariantOfMap',
	[17] = 'DesyncedDownloadingMap',
	[18] = 'DesyncedCreatingReport',
	[19] = 'InGameSavingMap',
}

pf.client_changed_state_new_state = ProtoField.uint16(
	"fgp.client_changed_state.new_state", "newState", base.DEC, ClientMultiplayerStateType, 0, "ClientMultiplayerStateType"
)

synchronizer_actions[0x03] = {
	name = 'ClientChangedState',
	dissect = function(pos, tvbuf, pktinfo, tree, is_server)
		if is_server then
			return pos, true
		end

		tree:add(pf.client_changed_state_new_state, tvbuf:range(pos, 1))
		pos = pos + 1
		return pos, false
	end,
}

synchronizer_actions[0x04] = {
	name = 'ClientShouldStartSendingTickClosures',
	len = 4,
}


GameActionType = {
	[0] = 'Nothing',
	[1] = 'GameCreatedFromScenario',
	[2] = 'ShowNextDialog',
	[3] = 'PlayerMinedTile',
	[4] = 'PlayerBuiltTile',
	[5] = 'RobotBuiltTile',
	[6] = 'RobotMinedTile',
	[7] = 'GuiTextChanged',
	[8] = 'EntityRenamed',
	[9] = 'ConsoleChat',
	[10] = 'ConsoleCommand',
	[11] = 'PlayerBanned',
	[12] = 'PlayerUnBanned',
	[13] = 'PlayerKicked',
	[14] = 'PlayerPlacedEquipment',
	[15] = 'PlayerRemovedEquipment',
	[16] = 'GuiOpened',
	[17] = 'GuiClosed',
	[18] = 'PlayerPipette',
	[19] = 'PlayerRotatedEntity',
	[20] = 'ModItemOpened',
	[21] = 'ChunkCharted',
	[22] = 'ForcesMerging',
	[23] = 'ForcesMerged',
	[24] = 'TrainChangedState',
	[25] = 'TrainScheduleChanged',
	[26] = 'ChunkDeleted',
	[27] = 'PreChunkDeleted',
	[28] = 'SurfaceImported',
	[29] = 'SurfaceRenamed',
	[30] = 'ChartTagAdded',
	[31] = 'ChartTagModified',
	[32] = 'ChartTagRemoved',
	[33] = 'LuaShortcut',
	[34] = 'PostEntityDied',
	[35] = 'StringTranslated',
	[36] = 'ScriptTriggerEffect',
	[37] = 'PreScriptInventoryResized',
	[38] = 'ScriptInventoryResized',
	[39] = 'ScriptSetTiles',
	[40] = 'PlayerRespawned',
	[41] = 'RocketLaunched',
	[42] = 'RocketLaunchOrdered',
	[43] = 'PlayerPickedUpItem',
	[44] = 'PlayerBuiltEntity',
	[45] = 'EntityDied',
	[46] = 'EntityDamaged',
	[47] = 'SectorScanned',
	[48] = 'PrePlayerMinedEntity',
	[49] = 'PlayerMinedItem',
	[50] = 'PlayerMinedEntity',
	[51] = 'ResearchStarted',
	[52] = 'ResearchFinished',
	[53] = 'ResearchReversed',
	[54] = 'FirstLabCreated',
	[55] = 'TechnologyEffectsReset',
	[56] = 'ForceReset',
	[57] = 'ChunkGenerated',
	[58] = 'PlayerCraftedItem',
	[59] = 'PrePlayerCraftedItem',
	[60] = 'PlayerCancelledCrafting',
	[61] = 'RobotBuiltEntity',
	[62] = 'PreRobotMinedEntity',
	[63] = 'PreRobotExplodedCliff',
	[64] = 'RobotExplodedCliff',
	[65] = 'RobotMinedItem',
	[66] = 'RobotMinedEntity',
	[67] = 'EntityMarkedForDeconstruction',
	[68] = 'EntityDeconstructionCanceled',
	[69] = 'EntityMarkedForUpgrade',
	[70] = 'EntityUpgradeCanceled',
	[71] = 'PreGhostDeconstructed',
	[72] = 'TriggerCreatedEntity',
	[73] = 'TriggerFiredArtillery',
	[74] = 'EntitySpawned',
	[75] = 'TrainCreated',
	[76] = 'DisplayResolutionChanged',
	[77] = 'DisplayScaleChanged',
	[78] = 'PlayerCreated',
	[79] = 'PlayerChangedPosition',
	[80] = 'ResourceDepleted',
	[81] = 'PlayerDrivingChangedState',
	[82] = 'ForceCreated',
	[83] = 'PlayerCursorStackChanged',
	[84] = 'PlayerQuickBarChanged',
	[85] = 'PlayerMainInventoryChanged',
	[86] = 'PlayerArmorInventoryChanged',
	[87] = 'PlayerAmmoInventoryChanged',
	[88] = 'PlayerGunInventoryChanged',
	[89] = 'PlayerTrashInventoryChanged',
	[90] = 'PreEntitySettingsPasted',
	[91] = 'EntitySettingsPasted',
	[92] = 'PrePlayerDied',
	[93] = 'PlayerDied',
	[94] = 'PlayerLeftGame',
	[95] = 'PlayerJoinedGame',
	[96] = 'GuiCheckedStateChanged',
	[97] = 'PlayerChangedSurface',
	[98] = 'SelectedEntityChanged',
	[99] = 'MarketOfferPurchased',
	[100] = 'PlayerDroppedItem',
	[101] = 'PlayerRepairedEntity',
	[102] = 'PlayerFastEntityTransferred',
	[103] = 'BiterBaseBuilt',
	[104] = 'PlayerChangedForce',
	[105] = 'GuiSelectionStateChanged',
	[106] = 'GuiSelectedTabChanged',
	[107] = 'RuntimeModSettingChanged',
	[108] = 'DifficultySettingsChanged',
	[109] = 'SurfaceCreated',
	[110] = 'SurfaceDeleted',
	[111] = 'PreSurfaceDeleted',
	[112] = 'PreSurfaceCleared',
	[113] = 'SurfaceCleared',
	[114] = 'GuiElemChanged',
	[115] = 'GuiLocationChanged',
	[116] = 'GuiValueChanged',
	[117] = 'GuiSwitchStateChanged',
	[118] = 'GuiClick',
	[119] = 'GuiConfirmed',
	[120] = 'BlueprintSelectArea',
	[121] = 'DeconstructionPlannerSelectArea',
	[122] = 'PlayerConfiguredBlueprint',
	[123] = 'PrePlayerRemoved',
	[124] = 'PlayerRemoved',
	[125] = 'PlayerUsedCapsule',
	[126] = 'PlayerToggledAltMode',
	[127] = 'PlayerPromoted',
	[128] = 'PlayerDemoted',
	[129] = 'PlayerMuted',
	[130] = 'PlayerUnmuted',
	[131] = 'PlayerCheatModeEnabled',
	[132] = 'PlayerCheatModeDisabled',
	[133] = 'PlayerToggledMapEditor',
	[134] = 'PrePlayerToggledMapEditor',
	[135] = 'CutsceneCancelled',
	[136] = 'CombatRobotExpired',
	[137] = 'LandMineArmed',
	[138] = 'CharacterCorpseExpired',
	[139] = 'SpiderCommandCompleted',
	[140] = 'PrePlayerLeftGame',
	[141] = 'ScriptPathRequestFinished',
	[142] = 'ScriptBuiltEntity',
	[143] = 'ScriptDestroyedEntity',
	[144] = 'ScriptRevivedEntity',
	[145] = 'AICommandCompleted',
	[146] = 'EntityCloned',
	[147] = 'AreaCloned',
	[148] = 'BrushCloned',
	[149] = 'OnPreBuild',
	[150] = 'CustomInput',
	[151] = 'SelectArea',
	[152] = 'AltSelectArea',
	[153] = 'CutsceneWaypointReached',
	[154] = 'UnitGroupCreated',
	[155] = 'UnitAddedToGroup',
	[156] = 'UnitGroupFinishedGathering',
	[157] = 'UnitRemovedFromGroup',
	[158] = 'BuildBaseArrived',
	[159] = 'ForceFriendsChanged',
	[160] = 'ForceCeaseFireChanged',
	[161] = 'EntityDestroyed',
	[162] = 'PlayerClickedGpsTag',
	[163] = 'PlayerFlushedFluid',
	[164] = 'PermissionGroupEdited',
	[165] = 'PrePermissionsStringImported',
	[166] = 'PermissionsStringImported',
	[167] = 'PrePermissionGroupDeleted',
	[168] = 'PermissionGroupDeleted',
	[169] = 'PermissionGroupAdded',
	[170] = 'PlayerConfiguredSpiderRemote',
	[171] = 'PlayerUsedSpiderRemote',
	[172] = 'EntityLogisticSlotChanged',
}

pf.monster_goblin  = ProtoField.uint32("fgp.map_ready.size", "size", base.DEC, nil, 0)
pf.monster_zombie  = ProtoField.uint32("fgp.map_ready.crc", "crc", base.DEC, nil, 0)
pf.monster_tick    = ProtoField.uint32("fgp.map_ready.update_tick", "updateTick", base.DEC, nil, 0)
pf.monster_hydra   = ProtoField.uint32("fgp.map_ready.autosave_interval", "autosaveInterval", base.DEC, nil, 0)
pf.monster_gryphon = ProtoField.uint32("fgp.map_ready.autosave_slots", "autosaveSlots", base.DEC, nil, 0)
pf.monster_gnome   =  ProtoField.uint8("fgp.map_ready.autosave_only_on_server", "autosaveOnlyOnServer", base.DEC, nil, 0)
pf.monster_gnome2  =  ProtoField.uint8("fgp.map_ready.non_blocking_saving", "nonBlockingSaving", base.DEC, nil, 0)

pf.mod_name_length =    ProtoField.uint8("fgp.mod_name.length", "length", base.DEC, nil, 0)
pf.mod_name_data =     ProtoField.string("fgp.mod_name.data", "data", base.ASCII)

pf.monster_bat_count =  ProtoField.uint8("fgp.map_ready.script_checksums.size", "size", base.DEC, nil, 0)
pf.monster_bat_check = ProtoField.uint32("fgp.map_ready.script_checksum", "checksum", base.HEX, nil, 0)

pf.monster_dog_count = ProtoField.uint8("fgp.map_ready.script_events.size", "size", base.DEC, nil, 0)

pf.monster_ghoul_count  =  ProtoField.uint8("fgp.script_registrations.standard_events.size", "size", base.DEC, nil, 0)
pf.monster_ghoul_item   = ProtoField.uint32("fgp.script_registrations.standard_events.item", "item", base.DEC, GameActionType, 0)
pf.monster_undead_count =  ProtoField.uint8("fgp.script_registrations.nth_tick_events.size", "size", base.DEC, nil, 0)
pf.monster_undead_item  = ProtoField.uint32("fgp.script_registrations.nth_tick_events.item", "item", base.DEC, nil, 0)

pf.monster_viper      =  ProtoField.uint8("fgp.script_registrations.standard_event_filters.size", "size", base.DEC, nil, 0)
pf.monster_viper_data = ProtoField.uint32("fgp.script_registrations.standard_event_filters.first", "first", base.DEC, GameActionType, 0)
pf.monster_viper_snd  = ProtoField.uint32("fgp.script_registrations.standard_event_filters.second", "second", base.DEC, nil, 0)

pf.monster_cobra = ProtoField.uint8("fgp.script_registrations.on_init", "onInit", base.DEC, nil, 0)
pf.monster_python = ProtoField.uint8("fgp.script_registrations.on_init", "onLoad", base.DEC, nil, 0)
pf.monster_python_data = ProtoField.uint8("fgp.script_registrations.on_configuration_changed", "onConfigurationChanged", base.DEC, nil, 0)

pf.monster_worm_count = ProtoField.uint8("fgp.map_ready.script_commands.size", "size", base.DEC, nil, 0)
pf.monster_worm_kind_count = ProtoField.uint8("fgp.map_ready.script_commands.second.size", "size", base.DEC, nil, 0)

pf.monster_worm_kind_length =  ProtoField.uint8("fgp.map_ready.script_commands.second.item.length", "length", base.DEC, nil, 0)
pf.monster_worm_kind_data   = ProtoField.string("fgp.map_ready.script_commands.second.item.data", "data", base.ASCII)

synchronizer_actions[0x05] = {
	name = 'MapReadyForDownload',
	dissect = function(pos, tvbuf, pktinfo, tree, is_server)
		if not is_server then
			return pos, true
		end

		local monster_start_pos = pos

		tree:add_le(pf.monster_goblin, tvbuf:range(pos, 4))
		pos = pos + 4
		tree:add_le(pf.monster_zombie, tvbuf:range(pos, 4))
		pos = pos + 4
		tree:add_le(pf.monster_tick, tvbuf:range(pos, 4))
		pos = pos + 4
		tree:add_le(pf.monster_hydra, tvbuf:range(pos, 4))
		pos = pos + 4
		tree:add_le(pf.monster_gryphon, tvbuf:range(pos, 4))
		pos = pos + 4
		tree:add_le(pf.monster_gnome, tvbuf:range(pos, 1))
		pos = pos + 1
		tree:add_le(pf.monster_gnome2, tvbuf:range(pos, 1))
		pos = pos + 1

		local bat_start_pos = pos
		local bat_count = tvbuf:range(pos, 1):uint()
		local bat_tree = tree:add(tvbuf:range(pos), "scriptChecksums: " .. bat_count)
		bat_tree:add(pf.monster_bat_count, tvbuf:range(pos, 1))
		pos = pos + 1

		for _=1, bat_count do
			local entry_start_pos = pos
			local entry_tree = bat_tree:add(tvbuf:range(pos), "entry")
			local mod_name
			pos, mod_name = decode_string(pos, tvbuf, entry_tree, "mod name", "mod_name")

			entry_tree:append_text(": " .. mod_name .. " " .. tvbuf:range(pos, 4):uint())
			entry_tree:add(pf.monster_bat_check, tvbuf:range(pos, 4))
			pos = pos + 4

			entry_tree.len = pos - entry_start_pos
		end
		bat_tree.len = pos - bat_start_pos

		local dog_start_pos = pos
		local dog_count = tvbuf:range(pos, 1):uint()
		local dog_tree = tree:add(tvbuf:range(pos), "scriptEvents: " .. dog_count)
		dog_tree:add(pf.monster_dog_count, tvbuf:range(pos, 1))
		pos = pos + 1

		for _=1, dog_count do
			local entry_start_pos = pos
			local entry_tree = dog_tree:add(tvbuf:range(pos), "ScriptRegistrations")
			local mod_name
			pos, mod_name = decode_string(pos, tvbuf, entry_tree, "mod name", "mod_name")

			entry_tree:append_text(": " .. mod_name)

			local ghoul_start_pos = pos
			local ghoul_count = tvbuf:range(pos, 1):uint()
			local ghoul_tree = entry_tree:add(tvbuf:range(pos), "standardEvents: " .. ghoul_count)
			ghoul_tree:add(pf.monster_ghoul_count, tvbuf:range(pos, 1))
			pos = pos + 1

			for _=1, ghoul_count do
				ghoul_tree:add_le(pf.monster_ghoul_item, tvbuf:range(pos, 4))
				pos = pos + 4
			end
			ghoul_tree.len = pos - ghoul_start_pos

			local undead_start_pos = pos
			local undead_count = tvbuf:range(pos, 1):uint()
			local undead_tree = entry_tree:add(tvbuf:range(pos), "nthTickEvents: " .. undead_count)
			undead_tree:add(pf.monster_undead_count, tvbuf:range(pos, 1))
			pos = pos + 1

			for _=1, undead_count do
				undead_tree:add_le(pf.monster_undead_item, tvbuf:range(pos, 4))
				pos = pos + 4
			end
			undead_tree.len = pos - undead_start_pos

			local viper_start_pos = pos
			local viper_count = tvbuf:range(pos, 1):uint()
			local viper_tree = entry_tree:add(tvbuf:range(pos), "standardEventFilters: " .. viper_count)
			viper_tree:add_le(pf.monster_viper, tvbuf:range(pos, 1))
			pos = pos + 1
			for _=1, viper_count do
				local value = tvbuf:range(pos, 4):le_uint()
				local label = "entry: " .. (GameActionType[value] or "Unknown") .. " (" .. value .. ")"
				local sub_entry_tree = viper_tree:add(tvbuf:range(pos, 8), label)
				sub_entry_tree:add_le(pf.monster_viper_data, tvbuf:range(pos, 4))
				pos = pos + 4
				sub_entry_tree:add_le(pf.monster_viper_snd, tvbuf:range(pos, 4))
				pos = pos + 4
			end
			viper_tree.len = pos - viper_start_pos

			entry_tree:add_le(pf.monster_cobra, tvbuf:range(pos, 1))
			pos = pos + 1

			local python = tvbuf:range(pos, 1):uint()
			entry_tree:add_le(pf.monster_python, tvbuf:range(pos, 1))
			pos = pos + 1
			entry_tree:add_le(pf.monster_python_data, tvbuf:range(pos, 1))
			pos = pos + 1

			entry_tree.len = pos - entry_start_pos
		end
		dog_tree.len = pos - dog_start_pos

		local worm_start_pos = pos
		local worm_count = tvbuf:range(pos, 1):uint()
		local worm_tree = tree:add(tvbuf:range(pos), "scriptCommands: " .. worm_count)
		worm_tree:add(pf.monster_worm_count, tvbuf:range(pos, 1))
		pos = pos + 1

		for _=1, worm_count do
			local entry_start_pos = pos
			local entry_tree = worm_tree:add(tvbuf:range(pos), "entry")
			local mod_name
			pos, mod_name = decode_string(pos, tvbuf, entry_tree, "mod name", "mod_name")

			entry_tree:append_text(": " .. mod_name)

			local worm_kind_count = tvbuf:range(pos, 1):uint()
			entry_tree:add(pf.monster_worm_kind_count, tvbuf:range(pos, 1))
			pos = pos + 1

			for _=1, worm_kind_count do
				local command
				pos, command = decode_string(pos, tvbuf, entry_tree, "item", "monster_worm_kind")
			end
		end
		worm_tree.len = pos - worm_start_pos

		return pos, false
	end,
}

synchronizer_actions[0x06] = {
	name = 'MapLoadingProgressUpdate',
	len = 1,
}

synchronizer_actions[0x07] = {
	name = 'MapSavingProgressUpdate',
	len = 1,
}

synchronizer_actions[0x08] = {
	name = 'SavingForUpdate',
	len = 0,
}

synchronizer_actions[0x09] = {
	name = 'MapDownloadingProgressUpdate',
	len = 1,
}

synchronizer_actions[0x0a] = {
	name = 'CatchingUpProgressUpdate',
	len = 1,
}

synchronizer_actions[0x0b] = {
	name = 'PeerDroppingProgressUpdate',
	len = 1,
}

synchronizer_actions[0x0c] = {
	name = 'PlayerDesynced',
}

synchronizer_actions[0x0d] = {
	name = 'BeginPause',
	clen = 0,
}

synchronizer_actions[0x0e] = {
	name = 'EndPause',
	clen = 0,
}

synchronizer_actions[0x0f] = {
	name = 'SkippedTickClosure',
	len = 4,
}

synchronizer_actions[0x10] = {
	name = 'SkippedTickClosureConfirm',
	len = 4,
}

synchronizer_actions[0x11] = {
	name = 'ChangeLatency',
	len = 1,
}

synchronizer_actions[0x12] = {
	name = 'IncreasedLatencyConfirm',
	len = 5,
}

synchronizer_actions[0x13] = {
	name = 'SavingCountDown',
}

synchronizer_actions[0x14] = {
	name = 'AuxiliaryDataReadyForDownload',
	len = 8,
}

synchronizer_actions[0x15] = {
	name = 'AuxiliaryDataDownloadFinished',
	len = 0,
}

SynchronizerActionType = {}
SynchronizerActionTypeEnum = {}
for id, data in pairs(synchronizer_actions) do
	SynchronizerActionType[id] = data.name
	SynchronizerActionTypeEnum[data.name] = id
end


pf.synchronizer_action_type = ProtoField.uint8("fgp.synchronizer_action.type", "type", base.HEX, SynchronizerActionType, 0, "SynchronizerMessageType")
pf.synchronizer_action_data = ProtoField.bytes("fgp.synchronizer_action.data", "data", base.SPACE, desc)

fe.synchronizer_action_type = "fgp.synchronizer_action.type"

function dissect_synchronizer_action(pos, tvbuf, pktinfo, tree, is_server)
	if pos + 1 > tvbuf:len() then
		pktinfo.cols.info:prepend("[Too short] ")
		tree:add_proto_expert_info(
			ef.too_short, "Packet too short for weird pebble"
		)
		return pos, true
	end

	local sync_type = tvbuf:range(pos, 1):uint()
	local sync_tree = tree:add(tvbuf:range(pos), SynchronizerActionType[sync_type] or "Unknown")

	sync_tree:add(pf.synchronizer_action_type, tvbuf:range(pos, 1))
	pos = pos + 1

	local hit_unknown = false
	if synchronizer_actions[sync_type] ~= nil then
		local action = synchronizer_actions[sync_type]
		if action.dissect then
			pos, hit_unknown = action.dissect(pos, tvbuf, pktinfo, sync_tree, is_server)

		else
			if not action.len then
				pktinfo.cols.info:prepend("[Sync #" .. sync_type .. " len unknown] ")
				sync_tree:add_proto_expert_info(
					ef.unknown, "Unknown length for " .. SynchronizerActionType[sync_type]
				)
				return pos, true
			end

			if pos + action.len > tvbuf:len() then
				pktinfo.cols.info:prepend("[Too short] ")
				sync_tree:add_proto_expert_info(
					ef.too_short, "Packet too short for " .. SynchronizerActionType[sync_type] .. " data"
				)
				return pos, true

			elseif action.len > 0 then
				sync_tree:add(pf.synchronizer_action_data, tvbuf:range(pos, action.len))
				pos = pos + action.len
			end
		end

		if not hit_unknown and is_server then
			sync_tree:add_le(pf.synchronizer_action_peer_id, tvbuf:range(pos, 2))
			pos = pos + 2
		end

	else
		pktinfo.cols.info:prepend("[Weird Unknown] ")
		tree:add_proto_expert_info(
			ef.unknown, "Unknown weird pebble id "..sync_type
		)
		return pos, true
	end

	return pos, hit_unknown
end



pf.block_number  = ProtoField.uint32("fgp.transfer_block.block_number", "blockNumber", base.DEC, nil, 0)
pf.download_data = ProtoField.bytes("fgp.transfer_block.data", "data", base.NONE)

fe.block_number = "fgp.transfer_block.block_number"

function dissect_transfer_block_request(pos, tvbuf, pktinfo, tree)
	if tvbuf:len() - pos < 4 then
		tree:add_proto_expert_info(ef.too_short)
		return
	end

	tree:add_le(pf.block_number, tvbuf:range(pos, 4))
	pos = pos + 4
	pktinfo.cols.info:append(" No=" .. fe.block_number().display)

	return pos
end

function dissect_transfer_block(pos, tvbuf, pktinfo, tree)
	if tvbuf:len() - pos < 4 then
		tree:add_proto_expert_info(ef.too_short)
		return
	end

	tree:add_le(pf.block_number, tvbuf:range(pos, 4))
	pos = pos + 4
	pktinfo.cols.info:append(" No=" .. fe.block_number().display)

	tree
		:add(pf.download_data, tvbuf:range(pos, tvbuf:len() - pos))
		:set_text("data (" .. tvbuf:len() - pos .. " bytes)")

	return tvbuf:len()
end



pf.game_port = ProtoField.uint16("fgp.lan_broadcast.game_port", "gamePort", base.DEC, nil, 0)
fe.game_port = "fgp.lan_broadcast.game_port"

function dissect_lan_broadcast(pos, tvbuf, pktinfo, tree)
	if tvbuf:len() - pos < 2 then
		tree:add_proto_expert_info(ef.too_short)
		return
	end

	tree:add_le(pf.game_port, tvbuf:range(pos, 2));
	pos = pos + 2

	pktinfo.cols.info:append(" Port=" .. fe.game_port().display)

	return pos
end

pf.unknown = ProtoField.bytes("fgp.unknown", "Undecoded Data", base.SPACE)


pf.fragment  = ProtoField.framenum("fgp.fragment", "Fragment",base.NONE, frametype.NONE, 0, "Fragment")
pf.fragments = ProtoField.bytes("fgp.fragments", "Fragments", base.SPACE, "Fragments")

local fgp = Proto("fgp", "Factorio Game Protocol")
fgp.fields = values(pf)

for k, v in pairs(fe) do
	fe[k] = Field.new(v)
end

fgp.experts = values(ef)


-- Partial packet fragments data
-- This is an table of msg_id to fragment data
local fragments = {}

-- fragment_data_format = {
--     state = "bulid" or "end" or "complete",
--     last_seq = frag_number of last fragment
--     parts = {
--         [frag_number] = {
--             bytes = ByteBuffer,
--             len = length of the bytes
--             number = packet number it was first observed in
--         }
--     }
-- }


function fgp.init()
	fragments = {}
end

function fgp.dissector(tvbuf, pktinfo, root)
	pktinfo.cols.protocol:set("Factorio")
	local tree = root:add(fgp, tvbuf:range(0, pktlen))
	local pktlen = tvbuf:reported_length_remaining()
	local pos = 0

	pos = dissect_network_message_header(pos, tvbuf, pktinfo, tree)
	if not pos then
		return
	end

	if not fe.fragmented()() then
		dissect_network_message(pos, tvbuf, pktinfo, tree)
		return
	end

	-- Check reassembly
	local msg_id = fe.message_id()()
	local last = fe.last_frag()()
	local seq = fe.frag_number()()

	-- Server and client ids can overlap
	if fe.message_type()() % 2 == 0 then
		msg_id = msg_id + 0x00010000
	end

	-- Check if packet is fragmented without fragments
	-- This usually happens to give a confirm block
	if seq == 0 and last then
		if not fe.confirm()() then
			tree:add_proto_expert_info(
				ef.unnecessary, "Fragmented packet without fragments or confirm"
			)
		end

		-- Skip reassembly and decode normally
		dissect_network_message(pos, tvbuf, pktinfo, tree)
		return tvbuf:range(pos)
	end

	-- Rebuild message from fragments
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
		" Fragment, Msg: " .. fe.message_id().display .. ", Seq: "
		.. fe.frag_number().display .. ", Len: " .. pktlen - pos

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

		local message_tree = root:add(fgp, tvb:range())
		dissect_network_message(0, tvb, pktinfo, message_tree)

	-- Either incomplete or a fragment, show info
	else
		if last then
			pktinfo.cols.info:append("Last ")
		end
		pktinfo.cols.info:append(
			"Frag Msg=" .. fe.message_id().display
			.. " Seq=" .. fe.frag_number().display
			.. " Len=" .. pktlen - pos
		)
	end
end



DissectorTable.get("udp.port"):add(default_settings.broadcast, fgp)
DissectorTable.get("udp.port"):add(default_settings.port, fgp)
