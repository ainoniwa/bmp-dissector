 -- #################################################
-- BGP Monitoring protocol dissector
-- Refer:
--   https://tools.ietf.org/id/draft-ietf-grow-bmp-07.txt
-- #################################################

-- =================================================
--     BGP Monitoring Protocol
-- =================================================
bmp_proto = Proto("bmp","BGP Monitoring Protocol")

-- =================================
--     Util
-- =================================
local VALS_BOOL	= {[0] = "False", [1] = "True"}
local BMPv1_HEADER_LEN = 44
local BGP_MARKER_LEN   = 16

BMPReader = {}
BMPReader.new = function(version, buf, offset)
    local self = {}
    offset = offset or 0
    proto_version = version

    self.read = function(length)
        local r = buf(offset, length)
        offset = offset + length
        return r
    end

    self.read_all = function()
        local r = buf(offset, buf:len() - offset)
        offset = buf:len()
        return r
    end

    self.skip = function(length)
        offset = offset + length
    end

    self.is_tail = function()
        if offset >= buf:len() then
            return true
        else
            return false
        end
    end

    self.get_version = function()
        return proto_version
    end
     
    return self
end

-- =================================
--     4. BMP Message Format
-- =================================
fields = {}

-- 4.1. Common Header
fields['bmp.version'] = ProtoField.uint8("bmp.version", "Version", base.HEX)
fields['bmp.length'] = ProtoField.uint32("bmp.length", "Length")
fields['bmp.type'] = ProtoField.uint8("bmp.type", "Type", base.HEX)

-- 4.2. Per-Peer Header
fields['bmp.peer.type'] = ProtoField.uint8("bmp.peer.type", "Peer Type", base.HEX)
fields['bmp.peer.flags'] = ProtoField.uint8("bmp.peer.flags", "Peer Flags", base.HEX)
fields['bmp.peer.flags.v'] = ProtoField.uint8("bmp.peer.flags", "address type", base.HEX, VALS_BOOL, 0x80)
fields['bmp.peer.flags.l'] = ProtoField.uint8("bmp.peer.flags", "policy", base.HEX, VALS_BOOL, 0x40)
fields['bmp.peer.dist']  = ProtoField.uint64("bmp.peer.dist", "Peer Distinguisher")
fields['bmp.peer.addr_v4'] = ProtoField.ipv4("bmp.peer.addr", "Peer address")
fields['bmp.peer.addr_v6'] = ProtoField.ipv6("bmp.peer.addr", "Peer address")
fields['bmp.peer.as'] = ProtoField.uint64("bmp.peer.as", "Peer AS")
fields['bmp.peer.id'] = ProtoField.ipv4("bmp.peer.id", "Peer BGP ID")
fields['bmp.peer.ts_sec'] = ProtoField.uint64("bmp.peer.ts_sec", "Timestamp[sec]")
fields['bmp.peer.ts_msec'] = ProtoField.uint64("bmp.peer.ts_msec", "Timestamp[msec]")

-- 4.3. Initiation Message
fields['bmp.init.type'] = ProtoField.uint16("bmp.init.type", "Information type")
fields['bmp.init.length'] = ProtoField.uint16("bmp.init.length", "Length")
fields['bmp.init.info'] = ProtoField.string("bmp.init.info", "Information")

-- 4.4. Termination Message
fields['bmp.termination.type'] = ProtoField.uint16("bmp.termination.type", "Termination type")
fields['bmp.termination.length'] = ProtoField.uint16("bmp.termination.length", "Length")
fields['bmp.termination.reason'] = ProtoField.uint16("bmp.termination.reason", "Reason")
fields['bmp.termination.info'] = ProtoField.string("bmp.termination.info", "Information")

-- 4.5. Route Monitoring
-- None.

-- 4.6. Stats Reports
fields['bmp.stat.count'] = ProtoField.uint32("bmp.stat.count", "Stat count")
fields['bmp.stat.type'] = ProtoField.uint16("bmp.stat.type", "Stat type")
fields['bmp.stat.length'] = ProtoField.uint16("bmp.stat.length", "Stat length")
fields['bmp.stat.data32'] = ProtoField.uint32("bmp.stat.data", "Stat data")
fields['bmp.stat.data64'] = ProtoField.uint64("bmp.stat.data", "Stat data")

-- 4.7. Peer Down Notification
fields['bmp.peer_down.reason'] = ProtoField.uint8("bmp.peer_down.reason", "Reason")

-- 4.8. Peer Up Notification
fields['bmp.peer_up.local_addr_v4'] = ProtoField.ipv4("bmp.peer_up.local_addr", "Local address")
fields['bmp.peer_up.local_addr_v6'] = ProtoField.ipv6("bmp.peer_up.local_addr", "Local address")
fields['bmp.peer_up.local_port'] = ProtoField.uint16("bmp.peer_up.local_port", "Local Port")
fields['bmp.peer_up.remote_port'] = ProtoField.uint16("bmp.peer_up.remote_port", "Peer Port")

-- Register protocol fields
for i, v in pairs(fields) do table.insert(bmp_proto.fields, v) end

bmp_type = {
    [0] = "Route Monitoring",
    [1] = "Statistics Report",
    [2] = "Peer Down Notification",
    [3] = "Peer Up Notification",
    [4] = "Initiation Message",
    [5] = "Termination Message",
}

peer_type = {
    [0] = "Global Instance Peer",
    [1] = "L3 VPN Instance Peer",
}

peer_flags_v = {
    [0] = "IPv4",
    [1] = "IPv6",
}

peer_flags_l = {
    [0] = "pre-policy Adj-RIB-In",
    [1] = "post-policy Adj-RIB-In",
}

information_type = {
    [0] = "String",
    [1] = "sysDescr",
    [2] = "sysName",
}

termination_type = {
    [0] = "String",
    [1] = "Reason",
}

termination_reason = {
    [0] = "Session administratively closed",
    [1] = "Unspecified reason",
    [2] = "Out of resources",
    [3] = "Redundant connection",
}

peer_down_reason = {
    [1] = "Closed by the local system with a notification",
    [2] = "Closed by the local system without a notification",
    [3] = "Closed by the remote system with a notification",
    [4] = "Closed by the remote system without a notification"
}

stat_type = {
    [0] = "Number of prefixes rejected by inbound policy",
    [1] = "Number of (known) duplicate prefix advertisements",
    [2] = "Number of (known) duplicate withdraws",
    [3] = "Number of updates invalidated due to CLUSTER_LIST loop",
    [4] = "Number of updates invalidated due to AS_PATH loop",
    [5] = "Number of updates invalidated due to ORIGINATOR_ID",
    [6] = "Number of updates invalidated due to AS_CONFED loop",
    [7] = "Number of routes in Adj-RIBs-In",
    [8] = "Number of routes in Loc-RIB",
}


-- ---------------------------------
--     4.1. Common Header
-- ---------------------------------
function bmp_proto.dissector(buf, pinfo, tree)
    local space_for_length_range = 6 
    local offset = 0
    local info = {}
    while offset + space_for_length_range < buf:len() do

        local _version_range = buf(offset,1)
        local _version = _version_range:uint()

        local _type_range = _version > 1 and buf(offset+5,1) or buf(offset+1,1)
        local _type = _type_range:uint()

		local _length_range = _version > 1 and buf(offset+1,4) 
		local _length = _version > 1 and _length_range:uint() or pdu_v1_length(_type, buf, offset)

        if _length == nil then
            pinfo.desegment_offset = offset
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            return

        elseif offset + _length > buf:len() then
            pinfo.can_desegment = 1
            pinfo.desegment_len = offset + _length - buf:len()
            pinfo.desegment_offset = 0
            return
        end
        local bmp_tree = tree:add(bmp_proto, buf(offset, _length))
        bmp_tree:set_text("BGP Monitoring Protocol, Type: " .. bmp_type[_type])
        bmp_tree:add(fields['bmp.version'], _version_range)
        bmp_tree:add(fields['bmp.type'], _type_range):append_text(" (" .. bmp_type[_type] .. ")")
        if _version > 1 then 
            bmp_tree:add(fields['bmp.length'], _length_range) 
        end

        local reader = BMPReader.new(_version, buf(offset, _length))
        reader.skip(_version > 1 and 6 or 2) 
        offset = offset + _length 

        if bmp_type[_type] == "Route Monitoring" then
            table.insert(info, "Route Monitoring")
            bmp_route_monitoring(reader, pinfo, bmp_tree)

        elseif bmp_type[_type] == "Statistics Report" then
            table.insert(info, "Statistics Report")
            bmp_statistics(reader, pinfo, bmp_tree)

        elseif bmp_type[_type] == "Peer Down Notification" then
            table.insert(info, "Peer Down Notification")
            bmp_peer_down(reader, pinfo, bmp_tree)

        elseif bmp_type[_type] == "Peer Up Notification" then
            table.insert(info, "Peer Up Notification")
            bmp_peer_up(reader, pinfo, bmp_tree)

        elseif bmp_type[_type] == "Initiation Message" then
            table.insert(info, "Initiation Message")
            bmp_init(reader, pinfo, bmp_tree)

        elseif bmp_type[_type] == "Termination Message" then
            table.insert(info, "Termination Message")
            bmp_termination(reader, pinfo, bmp_tree)
        end
    end
    pinfo.cols.protocol = "BMP"
    pinfo.cols.info = table.concat(info, ", ")

    if  offset < buf:len() then
        pinfo.desegment_offset = offset
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return
    end       
end

function pdu_v1_length(type, buf, offset) 
    local bmp_payload_offset = offset + BMPv1_HEADER_LEN


    if bmp_type[type] == "Route Monitoring" then
        if bmp_payload_offset + BGP_MARKER_LEN + 2 > buf:len() then return nil end
        local _bgp_length = buf(bmp_payload_offset+BGP_MARKER_LEN,2):uint()
        return BMPv1_HEADER_LEN + _bgp_length

    elseif bmp_type[type] == "Statistics Report" then
        if bmp_payload_offset + 4 > buf:len() then return nil end
        local _count = buf(bmp_payload_offset,4):uint()
        local payload_length = 0
        local next_stat_length_offset = bmp_payload_offset + 6
        for i=1,_count do
            if next_stat_length_offset + 2 > buf:len() then return nil end
            local stat_length = buf(next_stat_length_offset,2):uint()
            next_stat_length_offset = next_stat_length_offset + stat_length + 4
            payload_length = payload_length + stat_length
        end
        payload_length = payload_length + 4 + _count * 4
        return BMPv1_HEADER_LEN + payload_length

    elseif bmp_type[type] == "Peer Down Notification" then
        local _reason = buf(bmp_payload_offset,1):uint()

        if peer_down_reason[_reason] == "Closed by the local system with a notification"
           or peer_down_reason[_reason] == "Closed by the remote system with a notification" then
            local _bgp_length = buf(bmp_payload_offset+1+BGP_MARKER_LEN,2):uint()
            return BMPv1_HEADER_LEN + _bgp_length

        else
            return BMPv1_HEADER_LEN + 1
        end
    end

    return nil
end

-- ---------------------------------
--     4.2. Per-Peer Header
-- ---------------------------------
function bmp_peer(reader, pinfo, tree)
    local _type_range = reader.read(1)
    local _type = _type_range:uint()
    tree:add(fields['bmp.peer.type'], _type_range):append_text(" (" .. peer_type[_type] .. ")")
    local _flags_range = reader.read(1)
    local _flags_v = _flags_range:bitfield(0,1)
    local _flags_l = _flags_range:bitfield(1,1)
    flags_tree = tree:add(fields['bmp.peer.flags'], _flags_range)
    flags_tree:add(fields['bmp.peer.flags.v'], _flags_range):append_text(" (" .. peer_flags_v[_flags_v] .. ")")
    if reader.get_version() > 1 then
        flags_tree:add(fields['bmp.peer.flags.l'], _flags_range):append_text(" (" .. peer_flags_l[_flags_l] .. ")")
    end
    tree:add(fields['bmp.peer.dist'], reader.read(8))

    if peer_flags_v[_flags_v] == "IPv4" then
        reader.skip(12)
        tree:add(fields['bmp.peer.addr_v4'], reader.read(4))
    else
        tree:add(fields['bmp.peer.addr_v6'], reader.read(16))
    end
    tree:add(fields['bmp.peer.as'], reader.read(4))
    tree:add(fields['bmp.peer.id'], reader.read(4))
    tree:add(fields['bmp.peer.ts_sec'], reader.read(4))
    tree:add(fields['bmp.peer.ts_msec'], reader.read(4))

    return _flags_v
end


-- ---------------------------------
--     4.3. Initiation Message
-- ---------------------------------
function bmp_init(reader, pinfo, tree)
    while not reader.is_tail() do
        local _type_range = reader.read(2)
        local _length_range = reader.read(2)

        local _type = _type_range:uint()
        local _length = _length_range:uint()

        tree:add(fields['bmp.init.type'], _type_range):append_text(" (" .. information_type[_type] .. ")")
        tree:add(fields['bmp.init.length'], _length_range)

        if information_type[_type] == "String" then
            tree:add(fields['bmp.init.info'], reader.read(_length))
        elseif information_type[_type] == "sysDescr" then
            tree:add(fields['bmp.init.info'], reader.read(_length))
        elseif information_type[_type] == "sysName" then
            tree:add(fields['bmp.init.info'], reader.read(_length))
        end
    end
end


-- ---------------------------------
--     4.4. Termination Message
-- ---------------------------------
function bmp_termination(reader, pinfo, tree)
    while not reader.is_tail() do
        local _type_range = reader.read(2)
        local _length_range = reader.read(2)

        local _type = _type_range:uint()
        local _length = _length_range:uint()

        tree:add(fields['bmp.termination.type'], _type_range):append_text(" (" .. termination_type[_type] .. ")")
        tree:add(fields['bmp.termination.length'], _length_range)

        if termination_type[_type] == "Reason" then
            local _reason_range = reader.read(_length)
            local _reason = _type_range:uint()

            tree:add(fields['bmp.termination.reason'], _reason_range):append_text(" (" .. termination_reason[_reason] .. ")")
        elseif termination_type[_type] == "String" then
            tree:add(fields['bmp.termination.info'], reader.read(_length))
        end
    end
end


-- ---------------------------------
--     4.5. Route Monitoring
-- ---------------------------------
function bmp_route_monitoring(reader, pinfo, tree)
    bmp_peer(reader, pinfo, tree)
    bgp = DissectorTable.get("tcp.port"):get_dissector("179")
    bgp:call(reader.read_all():tvb(), pinfo, tree)
end


-- ---------------------------------
--     4.6. Stats Reports
-- ---------------------------------
function bmp_statistics(reader, pinfo, tree)
    bmp_peer(reader, pinfo, tree)
    local _count_range = reader.read(4)
    local _count = _count_range:uint()
    tree:add(fields['bmp.stat.count'], _count_range)

    for i=1, _count do
        local _type_range = reader.read(2)
        local _length_range = reader.read(2)
        local _type = _type_range:uint()
        local _length = _length_range:uint()
        tree:add(fields['bmp.stat.type'], _type_range):append_text(" (" .. stat_type[_type] .. ")")
        tree:add(fields['bmp.stat.length'], _length_range)

        if stat_type[_type] == "Number of prefixes rejected by inbound policy" then
            tree:add(fields['bmp.stat.data32'], reader.read(4))

        elseif stat_type[_type] == "Number of (known) duplicate prefix advertisements" then
            tree:add(fields['bmp.stat.data32'], reader.read(4))

        elseif stat_type[_type] == "Number of (known) duplicate withdraws" then
            tree:add(fields['bmp.stat.data32'], reader.read(4))

        elseif stat_type[_type] == "Number of updates invalidated due to CLUSTER_LIST loop" then
            tree:add(fields['bmp.stat.data32'], reader.read(4))

        elseif stat_type[_type] == "Number of updates invalidated due to AS_PATH loop" then
            tree:add(fields['bmp.stat.data32'], reader.read(4))

        elseif stat_type[_type] == "Number of updates invalidated due to ORIGINATOR_ID" then
            tree:add(fields['bmp.stat.data32'], reader.read(4))

        elseif stat_type[_type] == "Number of updates invalidated due to AS_CONFED loop" then
            tree:add(fields['bmp.stat.data32'], reader.read(4))

        elseif stat_type[_type] == "Number of routes in Adj-RIBs-In" then
            tree:add(fields['bmp.stat.data64'], reader.read(8))

        elseif stat_type[_type] == "Number of routes in Loc-RIB" then
            tree:add(fields['bmp.stat.data64'], reader.read(8))

        end
    end

end


-- ---------------------------------
--     4.7. Peer Down Notification
-- ---------------------------------
function bmp_peer_down(reader, pinfo, tree)
    local _flags_v = bmp_peer(reader, pinfo, tree)
    local _reason_range = reader.read(1)
    local _reason = _reason_range:uint()
    tree:add(fields['bmp.peer_down.reason'], _reason_range)

    if _reason < 4 then
        bgp = DissectorTable.get("tcp.port"):get_dissector("179")
        bgp:call(reader.read_all():tvb(), pinfo, tree)
    end
end


-- ---------------------------------
--     4.8. Peer Up Notification
-- ---------------------------------
function bmp_peer_up(reader, pinfo, tree)
    local _flags_v = bmp_peer(reader, pinfo, tree)

    if peer_flags_v[_flags_v] == "IPv4" then
        reader.skip(12)
        tree:add(fields['bmp.peer_up.local_addr_v4'], reader.read(4))
    else
        tree:add(fields['bmp.peer_up.local_addr_v6'], reader.read(16))
    end
    tree:add(fields['bmp.peer_up.local_port'], reader.read(2))
    tree:add(fields['bmp.peer_up.remote_port'], reader.read(2))

    bgp = DissectorTable.get("tcp.port"):get_dissector("179")
    bgp:call(reader.read_all():tvb(), pinfo, tree)
end


-- =================================================
--     Register bmp_proto
-- =================================================
DissectorTable.get("tcp.port"):add(11019, bmp_proto)
