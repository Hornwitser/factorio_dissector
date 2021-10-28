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

	if msg_type == NetworkMessageTypeEnum.Ping then
		pos = dissect_ping(pos, tvbuf, pktinfo, msg_tree)

	elseif msg_type == NetworkMessageTypeEnum.PingReply then
		pos = dissect_ping(pos, tvbuf, pktinfo, msg_tree)

	elseif msg_type == NetworkMessageTypeEnum.ConnectionRequest then
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

	elseif msg_type == NetworkMessageTypeEnum.GetOwnAddress then
		pos = dissect_get_own_address(pos, tvbuf, pktinfo, msg_tree)

	elseif msg_type == NetworkMessageTypeEnum.GetOwnAddressReply then
		pos = dissect_get_own_address_reply(pos, tvbuf, pktinfo, msg_tree)

	elseif msg_type == NetworkMessageTypeEnum.NatPunchRequest then
		pos = dissect_nat_punch_request(pos, tvbuf, pktinfo, msg_tree)

	elseif msg_type == NetworkMessageTypeEnum.NatPunch then
		-- These look like they are always empty

	elseif msg_type == NetworkMessageTypeEnum.TransferBlockRequest then
		pos = dissect_transfer_block_request(pos, tvbuf, pktinfo, msg_tree)

	elseif msg_type == NetworkMessageTypeEnum.TransferBlock then
		pos = dissect_transfer_block(pos, tvbuf, pktinfo, msg_tree)

	elseif msg_type == NetworkMessageTypeEnum.RequestForHeartbeatWhenDisconnecting then
		pos = dissect_heartbeat_request(pos, tvbuf, pktinfo, msg_tree)

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


pf.ping_number = ProtoField.uint16("fgp.ping.number", "number", base.DEC, nil, 0)

function dissect_ping(pos, tvbuf, pktinfo, tree)
	local number = tvbuf:range(pos, 2):le_uint()
	tree:add_le(pf.ping_number, tvbuf:range(pos, 2))
	pos = pos + 2

	pktinfo.cols.info:append(" Nr=" .. number)
	return pos
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

	pktinfo.cols.info:append(" Ver=" .. version .. " CID=" .. tvbuf:range(pos, 4):le_uint())

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

function dissect_connection_request_reply(pos, tvbuf, pktinfo, tree)
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

	pktinfo.cols.info:append(" Ver=" .. version .. " CID=" .. tvbuf:range(pos, 4):le_uint() .. " SID=" .. tvbuf:range(pos + 4, 4):le_uint())

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
		local req_tree = tree:add(tvbuf:range(pos, 1 + req_count * 4), "requestsForHeartbeat: " .. req_count)
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

		input_tree:add_le(pf.input_actions_size, count_range, count)
		input_tree:append_text(": " .. count)

		local last_index = 0xffff
		for _=1, count do
			pos, last_index, hit_unknown = dissect_input_action(pos, tvbuf, pktinfo, input_tree, last_index)
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


pf.input_action_string_length = ProtoField.uint32("fgp.input_action.string.length", "length", base.DEC, nil, 0)
pf.input_action_string_data = ProtoField.string("fgp.input_action.string.length", "data", base.ASCII)

input_actions = {}
input_actions[0] = {
	name = 'Nothing',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'StopWalking',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'BeginMining',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'StopMining',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ToggleDriving',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'OpenGui',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'CloseGui',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'OpenCharacterGui',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'OpenCurrentVehicleGui',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ConnectRollingStock',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'DisconnectRollingStock',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'SelectedEntityCleared',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ClearCursor',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ResetAssemblingMachine',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'OpenTechnologyGui',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'LaunchRocket',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'OpenProductionGui',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'StopRepair',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'CancelNewBlueprint',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'CloseBlueprintRecord',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'CopyEntitySettings',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'PasteEntitySettings',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'DestroyOpenedItem',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'CopyOpenedItem',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ToggleShowEntityInfo',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'SingleplayerInit',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'MultiplayerInit',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'DisconnectAllPlayers',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'SwitchToRenameStopGui',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'OpenBonusGui',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'OpenTrainsGui',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'OpenAchievementsGui',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'CycleBlueprintBookForwards',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'CycleBlueprintBookBackwards',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'CycleClipboardForwards',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'CycleClipboardBackwards',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'StopMovementInTheNextTick',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ToggleEnableVehicleLogisticsWhileMoving',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ToggleDeconstructionItemEntityFilterMode',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ToggleDeconstructionItemTileFilterMode',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'OpenLogisticGui',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'SelectNextValidGun',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ToggleMapEditor',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'DeleteBlueprintLibrary',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'GameCreatedFromScenario',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ActivateCopy',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ActivateCut',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ActivatePaste',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'Undo',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'TogglePersonalRoboport',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ToggleEquipmentMovementBonus',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'TogglePersonalLogisticRequests',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ToggleEntityLogisticRequests',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'StopBuildingByMoving',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'FlushOpenedEntityFluid',
	len = 0,
}

input_actions[#input_actions+1] = {
	name = 'ForceFullCRC',
	lern = 0,
}

input_actions[#input_actions+1] = {
	name = 'OpenTipsAndTricksGui',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'OpenBlueprintLibraryGui',
	len = 2,
}

input_actions[#input_actions+1] = {
	name = 'ChangeBlueprintLibraryTab',
	len = 2,
}

input_actions[#input_actions+1] = {
	name = 'DropItem',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'Build',
	len = 5,
}

input_actions[#input_actions+1] = {
	name = 'StartWalking',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'BeginMiningTerrain',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'ChangeRidingState',
	len = 2,
}

input_actions[#input_actions+1] = {
	name = 'OpenItem',
	len = 5,
}

input_actions[#input_actions+1] = {
	name = 'OpenParentOfOpenedItem',
	len = 2,
}

input_actions[#input_actions+1] = {
	name = 'ResetItem',
	len = 5,
}

input_actions[#input_actions+1] = {
	name = 'DestroyItem',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'OpenModItem',
	len = 6,
}

input_actions[#input_actions+1] = {
	name = 'OpenEquipment',
}

input_actions[#input_actions+1] = {
	name = 'CursorTransfer',
	len = 9,
}

input_actions[#input_actions+1] = {
	name = 'CursorSplit',
	len = 5,
}

input_actions[#input_actions+1] = {
	name = 'StackTransfer',
	len = 5,
}

input_actions[#input_actions+1] = {
	name = 'InventoryTransfer',
	len = 5,
}

-- ActionData::CrcData
pf.crc_data_crc         = ProtoField.uint32("fgp.input_action.crc_data.crc", "crc", base.DEC, nil, 0)
pf.crc_data_tick_of_crc = ProtoField.uint32("fgp.input_action.crc_data.tick_of_crc", "tickOfCrc",base.DEC, nil, 0)

input_actions[#input_actions+1] = {
	name = 'CheckCRCHeuristic',
	dissect = function(pos, tvbuf, pktinfo, tree)
		tree:add_le(pf.crc_data_crc, tvbuf:range(pos, 4))
		pos = pos + 4
		tree:add_le(pf.crc_data_tick_of_crc, tvbuf:range(pos, 4))
		pos = pos + 4

		return pos
	end
}

input_actions[#input_actions+1] = {
	name = 'Craft',
	len = 5,
}

input_actions[#input_actions+1] = {
	name = 'WireDragging',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'ChangeShootingState',
	len = 9,
}

input_actions[#input_actions+1] = {
	name = 'SetupAssemblingMachine',
}

input_actions[#input_actions+1] = {
	name = 'SelectedEntityChanged',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'SmartPipette',
}

input_actions[#input_actions+1] = {
	name = 'StackSplit',
	len = 2,
}

input_actions[#input_actions+1] = {
	name = 'InventorySplit',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'CancelCraft',
}

input_actions[#input_actions+1] = {
	name = 'SetFilter',
}

input_actions[#input_actions+1] = {
	name = 'CheckCRC',
	len = 9,
}

input_actions[#input_actions+1] = {
	name = 'SetCircuitCondition',
}

input_actions[#input_actions+1] = {
	name = 'SetSignal',
}

input_actions[#input_actions+1] = {
	name = 'StartResearch',
}

input_actions[#input_actions+1] = {
	name = 'SetLogisticFilterItem',
}

input_actions[#input_actions+1] = {
	name = 'SetLogisticFilterSignal',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SetCircuitModeOfOperation',
	len = 12,
}

input_actions[#input_actions+1] = {
	name = 'GuiClick',
}

input_actions[#input_actions+1] = {
	name = 'GuiConfirmed',
}

input_actions[#input_actions+1] = {
	name = 'WriteToConsole',
	dissect = function(pos, tvbuf, pktinfo, tree)
		pos = decode_string(pos, tvbuf, tree, "string", "input_action_string")
		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'MarketOffer',
	len = 9,
}

input_actions[#input_actions+1] = {
	name = 'AddTrainStation',
	len = 9,
}

input_actions[#input_actions+1] = {
	name = 'ChangeTrainStopStation',
	dissect = function(pos, tvbuf, pktinfo, tree)
		pos = decode_string(pos, tvbuf, tree, "string", "input_action_string")
		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'ChangeActiveItemGroupForCrafting',
	len = 25,
}

input_actions[#input_actions+1] = {
	name = 'ChangeActiveItemGroupForFilters',
	len = 5,
}

input_actions[#input_actions+1] = {
	name = 'ChangeActiveCharacterTab',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'GuiTextChanged',
}

input_actions[#input_actions+1] = {
	name = 'GuiCheckedStateChanged',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'GuiSelectionStateChanged',
}

input_actions[#input_actions+1] = {
	name = 'GuiSelectedTabChanged',
}

input_actions[#input_actions+1] = {
	name = 'GuiValueChanged',
	len = 23,
}

input_actions[#input_actions+1] = {
	name = 'GuiSwitchStateChanged',
}

input_actions[#input_actions+1] = {
	name = 'GuiLocationChanged',
	len = 23,
}

input_actions[#input_actions+1] = {
	name = 'PlaceEquipment',
}

input_actions[#input_actions+1] = {
	name = 'TakeEquipment',
	dissect = function(pos, tvbuf, pktinfo, tree)
		local len = 15 + tvbuf:range(pos + 5, 1):uint() * 4
		tree:add(pf.input_action_data, tvbuf:range(pos, len))
		pos = pos + len

		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'UseItem',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'SendSpidertron',
}

input_actions[#input_actions+1] = {
	name = 'UseArtilleryRemote',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'SetInventoryBar',
	len = 6,
}

input_actions[#input_actions+1] = {
	name = 'MoveOnZoom',
}

input_actions[#input_actions+1] = {
	name = 'StartRepair',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'Deconstruct',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'Upgrade',
}

input_actions[#input_actions+1] = {
	name = 'Copy',
	len = 2,
}

input_actions[#input_actions+1] = {
	name = 'AlternativeCopy',
}

input_actions[#input_actions+1] = {
	name = 'SelectBlueprintEntities',
}

input_actions[#input_actions+1] = {
	name = 'AltSelectBlueprintEntities',
}

input_actions[#input_actions+1] = {
	name = 'SetupBlueprint',
}

input_actions[#input_actions+1] = {
	name = 'SetupSingleBlueprintRecord',
}

input_actions[#input_actions+1] = {
	name = 'CopyOpenedBlueprint',
}

input_actions[#input_actions+1] = {
	name = 'ReassignBlueprint',
}

input_actions[#input_actions+1] = {
	name = 'OpenBlueprintRecord',
}

input_actions[#input_actions+1] = {
	name = 'GrabBlueprintRecord',
	dissect = function(pos, tvbuf, pktinfo, tree)
		local len = 7 + tvbuf:range(pos + 4, 1):uint()
		tree:add(pf.input_action_data, tvbuf:range(pos, len))
		pos = pos + len

		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'DropBlueprintRecord',
}

input_actions[#input_actions+1] = {
	name = 'DeleteBlueprintRecord',
}

input_actions[#input_actions+1] = {
	name = 'UpgradeOpenedBlueprintByRecord',
}

input_actions[#input_actions+1] = {
	name = 'UpgradeOpenedBlueprintByItem',
}

input_actions[#input_actions+1] = {
	name = 'SpawnItem',
}

input_actions[#input_actions+1] = {
	name = 'SpawnItemStackTransfer',
}

input_actions[#input_actions+1] = {
	name = 'UpdateBlueprintShelf',
}

input_actions[#input_actions+1] = {
	name = 'TransferBlueprint',
	len = 13,
}

input_actions[#input_actions+1] = {
	name = 'TransferBlueprintImmediately',
	len = 10,
}

input_actions[#input_actions+1] = {
	name = 'EditBlueprintToolPreview',
}

input_actions[#input_actions+1] = {
	name = 'RemoveCables',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'ExportBlueprint',
}

input_actions[#input_actions+1] = {
	name = 'ImportBlueprint',
	len = 16,
}

input_actions[#input_actions+1] = {
	name = 'ImportBlueprintsFiltered',
	len = 6,
}

input_actions[#input_actions+1] = {
	name = 'PlayerJoinGame',
	dissect = function(pos, tvbuf, pktinfo, tree)
		local len = 7 + tvbuf:range(pos + 4, 1):uint()
		tree:add(pf.input_action_data, tvbuf:range(pos, len))
		pos = pos + len

		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'PlayerAdminChange',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'CancelDeconstruct',
	dissect = function(pos, tvbuf, pktinfo, tree)
		local length_range, length_value
		pos, length_range, length_value = decode_uint32v(pos, tvbuf)

		local len = length_value + 13
		tree:add(pf.input_action_data, tvbuf:range(pos, len))
		pos = pos + len

		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'CancelUpgrade',
	len = 5,
}

input_actions[#input_actions+1] = {
	name = 'ChangeArithmeticCombinatorParameters',
}

input_actions[#input_actions+1] = {
	name = 'ChangeDeciderCombinatorParameters',
}

input_actions[#input_actions+1] = {
	name = 'ChangeProgrammableSpeakerParameters',
}

input_actions[#input_actions+1] = {
	name = 'ChangeProgrammableSpeakerAlertParameters',
}

input_actions[#input_actions+1] = {
	name = 'ChangeProgrammableSpeakerCircuitParameters',
}

input_actions[#input_actions+1] = {
	name = 'SetVehicleAutomaticTargetingParameters',
}

input_actions[#input_actions+1] = {
	name = 'BuildTerrain',
}

input_actions[#input_actions+1] = {
	name = 'ChangeTrainWaitCondition',
	dissect = function(pos, tvbuf, pktinfo, tree)
		tree:add_le(tvbuf:range(pos, 4), "Unknown")
		pos = pos + 4

		local length_range, length_value
		pos, length_range, length_value = decode_uint32v(pos + 4, tvbuf)

		local len = length_value + 12
		tree:add(pf.input_action_data, tvbuf:range(pos, len))
		pos = pos + len

		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'ChangeTrainWaitConditionData',
}

-- ActionData::CustomInputData
pf.custom_input_id = ProtoField.uint16("fgp.input_action.custom_input_data.custom_input_id", "customInputID", base.DEC, nil, 0)
pf.custom_input_cursor_x = ProtoField.float("fgp.input_action.custom_input_data.cursor_position.x", "cursorPosition.x", nil, 0)
pf.custom_input_cursor_y = ProtoField.float("fgp.input_action.custom_input_data.cursor_position.y", "cursorPosition.y", nil, 0)

pf.custom_input_load = ProtoField.bool("fgp.input_action.custom_input_data.load", "load", 0, nil, 0)
pf.custom_input_selected_base_length = ProtoField.uint32("fgp.input_action.custom_input_data.selected_prototype_data.base_type.length", "length", base.DEC, nil, 0)
pf.custom_input_selected_base_data = ProtoField.string("fgp.input_action.custom_input_data.selected_prototype_data.base_type.data", "data", base.ASCII)
pf.custom_input_selected_derived_length = ProtoField.uint32("fgp.input_action.custom_input_data.selected_prototype_data.derived_type.length", "length", base.DEC, nil, 0)
pf.custom_input_selected_derived_data = ProtoField.string("fgp.input_action.custom_input_data.selected_prototype_data.derived_type.data", "data", base.ASCII)
pf.custom_input_selected_name_length = ProtoField.uint32("fgp.input_action.custom_input_data.selected_prototype_data.name.length", "length", base.DEC, nil, 0)
pf.custom_input_selected_name_data = ProtoField.string("fgp.input_action.custom_input_data.selected_prototype_data.name.data", "data", base.ASCII)

input_actions[#input_actions+1] = {
	name = 'CustomInput',
	dissect = function(pos, tvbuf, pktinfo, tree)
		tree:add_le(pf.custom_input_id, tvbuf:range(pos, 2))
		pos = pos + 2

		tree:add_le(pf.custom_input_cursor_x, tvbuf:range(pos, 4), tvbuf:range(pos, 4):le_int() / 256)
		pos = pos + 4

		tree:add_le(pf.custom_input_cursor_y, tvbuf:range(pos, 4), tvbuf:range(pos, 4):le_int() / 256)
		pos = pos + 4

		local load_selected = tvbuf:range(pos, 1):uint() == 1
		tree:add_le(pf.custom_input_load, tvbuf:range(pos, 1))
		pos = pos + 1

		if load_selected then
			pos = decode_string(pos, tvbuf, tree, "selectedPrototype.baseType", "custom_input_selected_base")
			pos = decode_string(pos, tvbuf, tree, "selectedPrototype.derivedType", "custom_input_selected_derived")
			pos = decode_string(pos, tvbuf, tree, "selectedPrototype.name", "custom_input_selected_name")
		end

		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'ChangeItemLabel',
	dissect = function(pos, tvbuf, pktinfo, tree)
		pos = decode_string(pos, tvbuf, tree, "string", "input_action_string")
		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'ChangeItemDescription',
	dissect = function(pos, tvbuf, pktinfo, tree)
		pos = decode_string(pos, tvbuf, tree, "string", "input_action_string")
		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'ChangeEntityLabel',
	dissect = function(pos, tvbuf, pktinfo, tree)
		pos = decode_string(pos, tvbuf, tree, "string", "input_action_string")
		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'BuildRail',
}

input_actions[#input_actions+1] = {
	name = 'CancelResearch',
	len = 12,
}

input_actions[#input_actions+1] = {
	name = 'SelectArea',
}

input_actions[#input_actions+1] = {
	name = 'AltSelectArea',
}

input_actions[#input_actions+1] = {
	name = 'ServerCommand',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'SetControllerLogisticTrashFilterItem',
}

input_actions[#input_actions+1] = {
	name = 'SetEntityLogisticTrashFilterItem',
}

input_actions[#input_actions+1] = {
	name = 'SetInfinityContainerFilterItem',
}

input_actions[#input_actions+1] = {
	name = 'SetInfinityPipeFilter',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'ModSettingsChanged',
	len = 7,
}

input_actions[#input_actions+1] = {
	name = 'SetEntityEnergyProperty',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'EditCustomTag',
	len = 2,
}

input_actions[#input_actions+1] = {
	name = 'EditPermissionGroup',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'ImportBlueprintString',
}

input_actions[#input_actions+1] = {
	name = 'ImportPermissionsString',
	dissect = function(pos, tvbuf, pktinfo, tree)
		pos = decode_string(pos, tvbuf, tree, "string", "input_action_string")
		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'ReloadScript',
	dissect = function(pos, tvbuf, pktinfo, tree)
		pos = decode_string(pos, tvbuf, tree, "string", "input_action_string")
		return pos
	end,
}

input_actions[#input_actions+1] = {
	name = 'ReloadScriptDataTooLarge',
}

input_actions[#input_actions+1] = {
	name = 'GuiElemChanged',
}

input_actions[#input_actions+1] = {
	name = 'BlueprintTransferQueueUpdate',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'DragTrainSchedule',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'DragTrainWaitCondition',
	len = 2,
}

input_actions[#input_actions+1] = {
	name = 'SelectItem',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'SelectEntitySlot',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'SelectTileSlot',
}

input_actions[#input_actions+1] = {
	name = 'SelectMapperSlot',
}

input_actions[#input_actions+1] = {
	name = 'DisplayResolutionChanged',
}

input_actions[#input_actions+1] = {
	name = 'QuickBarSetSlot',
}

input_actions[#input_actions+1] = {
	name = 'QuickBarPickSlot',
}

input_actions[#input_actions+1] = {
	name = 'QuickBarSetSelectedPage',
}

input_actions[#input_actions+1] = {
	name = 'PlayerLeaveGame',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'MapEditorAction',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'PutSpecialItemInMap',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'PutSpecialRecordInMap',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'ChangeMultiplayerConfig',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'AdminAction',
}

input_actions[#input_actions+1] = {
	name = 'LuaShortcut',
}

input_actions[#input_actions+1] = {
	name = 'TranslateString',
}

input_actions[#input_actions+1] = {
	name = 'FlushOpenedEntitySpecificFluid',
}

input_actions[#input_actions+1] = {
	name = 'ChangePickingState',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SelectedEntityChangedVeryClose',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SelectedEntityChangedVeryClosePrecise',
	len = 2,
}

input_actions[#input_actions+1] = {
	name = 'SelectedEntityChangedRelative',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'SelectedEntityChangedBasedOnUnitNumber',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'SetAutosortInventory',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SetFlatControllerGui',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SetRecipeNotifications',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SetAutoLaunchRocket',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SwitchConstantCombinatorState',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SwitchPowerSwitchState',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SwitchInserterFilterModeState',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SwitchConnectToLogisticNetwork',
	len = 1
}

input_actions[#input_actions+1] = {
	name = 'SetBehaviorMode',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'FastEntityTransfer',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'RotateEntity',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'FastEntitySplit',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SetTrainStopped',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'ChangeControllerSpeed',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'SetAllowCommands',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SetResearchFinishedStopsGame',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SetInserterMaxStackSize',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'OpenTrainGui',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'SetEntityColor',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'SetDeconstructionItemTreesAndRocksOnly',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SetDeconstructionItemTileSelectionMode',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'DeleteCustomTag',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'DeletePermissionGroup',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'AddPermissionGroup',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'SetInfinityContainerRemoveUnfilteredItems',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SetCarWeaponsControl',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SetRequestFromBuffers',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'ChangeActiveQuickBar',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'OpenPermissionsGui',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'DisplayScaleChanged',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'SetSplitterPriority',
	len = 1
}

input_actions[#input_actions+1] = {
	name = 'GrabInternalBlueprintFromText',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'SetHeatInterfaceTemperature',
	len = 8,
}

input_actions[#input_actions+1] = {
	name = 'SetHeatInterfaceMode',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'OpenTrainStationGui',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'RemoveTrainStation',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'GoToTrainStation',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'RenderModeChanged',
	len = 1,
}

input_actions[#input_actions+1] = {
	name = 'SetPlayerColor',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'PlayerClickedGpsTag',
}

input_actions[#input_actions+1] = {
	name = 'SetTrainsLimit',
	len = 4,
}

input_actions[#input_actions+1] = {
	name = 'ClearRecipeNotification',
}

input_actions[#input_actions+1] = {
	name = 'SetLinkedContainerLinkID',
	len = 4,
}

local InputActionType = {}
local InputActionTypeEnum = {}
for id, data in pairs(input_actions) do
	InputActionType[id] = data.name
	InputActionTypeEnum[data.name] = id
end

pf.input_actions_size = ProtoField.uint8("fgp.tick_closure.input_actions.size", "size", base.DEC, nil, 0)
pf.input_action_type         = ProtoField.uint8("fgp.input_action.type", "type", base.HEX, InputActionType, 0)
pf.input_action_player_index = ProtoField.uint16("fgp.input_action.player_index", "playerIndex", base.DEC, nil, 0)
pf.input_action_data         = ProtoField.bytes("fgp.input_action.data", "data", base.SPACE)


function dissect_input_action(pos, tvbuf, pktinfo, tree, last_index)
	local input_start_pos = pos
	local input_type = tvbuf:range(pos, 1):uint()
	local input_tree = tree:add(tvbuf:range(pos), "InputAction")
	input_tree:add(pf.input_action_type, tvbuf:range(pos, 1))
	pos = pos + 1

	local pi_delta_range, pi_delta_value
	pos, pi_delta_range, pi_delta_value = decode_uint16v(pos, tvbuf)
	local player_index  = bit32.band(last_index + pi_delta_value, 0xffff)
	input_tree:add(pf.input_action_player_index, pi_delta_range, player_index)

	local info = input_actions[input_type]
	if info ~= nil then
		input_tree:set_text(info.name)

		if info.dissect then
			pos = info.dissect(pos, tvbuf, pktinfo, input_tree)

		elseif info.len then
			if info.len ~= 0 then
				input_tree:add(pf.input_action_data, tvbuf:range(pos, info.len))
				pos = pos + info.len
			end

		else
			pktinfo.cols.info:prepend("[Input #" .. input_type .. " len unknown] ")
			input_tree:add_proto_expert_info(
				ef.unknown, "Unknown length for " .. InputActionType[input_type]
			)
			return pos, player_index, true

		end

	else
		pktinfo.cols.info:prepend("[Input #" .. input_type .. " unknown] ")
		input_tree:add_proto_expert_info(
			ef.unknown, "Unknown InputActionType " .. input_type
		)
		return pos, player_index, true
	end
	input_tree.len = pos - input_start_pos

	return pos, player_index, false
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
	len = 8,
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
pf.synchronizer_action_data = ProtoField.bytes("fgp.synchronizer_action.data", "data", base.SPACE)

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



pf.get_addr_number = ProtoField.uint16("fgp.get_own_address.number", "number", base.DEC, nil, 0)

function dissect_get_own_address(pos, tvbuf, pktinfo, tree)
	local number = tvbuf:range(pos, 2):le_uint()
	tree:add_le(pf.get_addr_number, tvbuf:range(pos, 2))
	pos = pos + 2

	pktinfo.cols.info:append(" Nr=" .. number)
	return pos
end

pf.get_addr_reply_number = ProtoField.uint16("fgp.get_own_address_reply.number", "number", base.DEC, nil, 0)
pf.get_addr_reply_addr_length = ProtoField.uint32("fgp.get_own_address_reply.reflexive_address.length", "length", base.DEC, nil, 0)
pf.get_addr_reply_addr_data = ProtoField.string("fgp.get_own_address_reply.reflexive_address.data", "data", base.ASCII)

function dissect_get_own_address_reply(pos, tvbuf, pktinfo, tree)
	local number = tvbuf:range(pos, 2):le_uint()
	tree:add_le(pf.get_addr_reply_number, tvbuf:range(pos, 2))
	pos = pos + 2

	pktinfo.cols.info:append(" Nr=" .. number)

	local start_pos = pos
	local length = tvbuf:range(pos, 4):le_uint()
	local string_tree = tree:add(tvbuf:range(pos + 4 + length), "reflexiveAddress")
	string_tree:add_le(pf.get_addr_reply_addr_length, tvbuf:range(pos, 4))
	pos = pos + 4

	local data = tvbuf:range(pos, length):string()
	string_tree:append_text(": " .. data)
	pktinfo.cols.info:append(" Addr=" .. data)

	string_tree:add(pf.get_addr_reply_addr_data, tvbuf:range(pos, length))
	pos = pos + length
	string_tree.len = pos - start_pos

	return pos
end

pf.punch_addr_length = ProtoField.uint32("fgp.nat_punch_request.addr.length", "length", base.DEC, nil, 0)
pf.punch_addr_data = ProtoField.string("fgp.nat_punch_request.addr.data", "data", base.ASCII)


function dissect_nat_punch_request(pos, tvbuf, pktinfo, tree)
	local start_pos = pos
	local length = tvbuf:range(pos, 4):le_uint()
	local string_tree = tree:add(tvbuf:range(pos + 4 + length), "addr")
	string_tree:add_le(pf.punch_addr_length, tvbuf:range(pos, 4))
	pos = pos + 4

	local data = tvbuf:range(pos, length):string()
	string_tree:append_text(": " .. data)
	pktinfo.cols.info:append(" Addr=" .. data)

	string_tree:add(pf.punch_addr_data, tvbuf:range(pos, length))
	pos = pos + length
	string_tree.len = pos - start_pos

	return pos
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


pf.heartbeat_request_next_sequence_id = ProtoField.uint32("fgp.request_for_heartbeat_when_disconnecting.next_sequenc_id", "nextSequenceID", base.DEC, nil, 0)
pf.heartbeat_request_size = ProtoField.uint8("fgp.request_for_heartbeat_when_disconnecting.requests.size", "size", base.DEC, nil, 0)
pf.heartbeat_request_item = ProtoField.uint32("fgp.request_for_heartbeat_when_disconnecting.requests.item", "item", base.DEC, nil, 0)

function dissect_heartbeat_request(pos, tvbuf, pktinfo, tree)
	if tvbuf:len() - pos < 5 then
		tree:add_proto_expert_info(ef.too_short)
		return
	end

	tree:add_le(pf.heartbeat_request_next_sequence_id, tvbuf:range(pos, 4))
	pos = pos + 4

	local req_tree_start_pos = pos;
	local req_tree = tree:add(tvbuf:range(pos), "requests")
	local req_size_range, req_size
	pos, req_size_range, req_size = decode_uint32v(pos, tvbuf)
	req_tree:add(pf.heartbeat_request_size, req_size_range, req_size)

	for _=1, req_size do
		req_tree:add_le(pf.heartbeat_request_item, tvbuf:range(pos, 4))
		pos = pos + 4
	end
	req_tree.len = pos - req_tree_start_pos

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

local fgp = Proto("Factorio", "Factorio Game Protocol")
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
