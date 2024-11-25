-- custom_udp_colored.lua
-- Enhanced Lua dissector for a custom UDP protocol with detailed packet differentiation and Info column marking
-- Includes packet coloring based on Message Type

-- Create a new protocol
local custom_udp_proto = Proto("customudp", "Custom UDP Protocol v2.0")

-- Define the fields of the protocol
local f_flags = ProtoField.uint16("customudp.flags", "Flags", base.HEX)
local f_fragment_offset = ProtoField.uint32("customudp.fragment_offset", "Fragment Offset", base.DEC)
local f_ack_number = ProtoField.uint32("customudp.ack_number", "ACK Number", base.DEC)
local f_data = ProtoField.bytes("customudp.data", "Data")
local f_crc16 = ProtoField.uint16("customudp.crc16", "CRC16 Checksum", base.HEX)
local f_message_type = ProtoField.string("customudp.message_type", "Message Type")
local f_color_field = ProtoField.string("udp.color_field", "UDP Coloring Field") -- Field for coloring

-- Add fields to the protocol
custom_udp_proto.fields = {f_flags, f_fragment_offset, f_ack_number, f_data, f_crc16, f_message_type, f_color_field}

-- Define flag bits as per the Python code (only lower 8 bits are used)
local FLAG_SYN           = 1 << 7  -- 0b10000000
local FLAG_ACK           = 1 << 6  -- 0b01000000
local FLAG_NACK          = 1 << 5  -- 0b00100000
local FLAG_FIN           = 1 << 4  -- 0b00010000
local FLAG_DATA          = 1 << 3  -- 0b00001000
local FLAG_FRAGMENTED    = 1 << 2  -- 0b00000100
local FLAG_LAST_FRAGMENT = 1 << 1  -- 0b00000010
local FLAG_KEEPALIVE     = 1 << 0  -- 0b00000001

-- Define message types based on flag combinations
local MESSAGE_TYPES = {
    [FLAG_SYN] = "SYN",
    [FLAG_SYN | FLAG_ACK] = "SYN-ACK",
    [FLAG_ACK] = "ACK",
    [FLAG_NACK] = "NACK",
    [FLAG_FIN] = "FIN",
    [FLAG_FIN | FLAG_ACK] = "FIN-ACK",
    [FLAG_KEEPALIVE] = "KeepAlive",
    [FLAG_DATA] = "Data",
    [FLAG_DATA | FLAG_FRAGMENTED] = "Fragmented Data",
    [FLAG_DATA | FLAG_FRAGMENTED | FLAG_LAST_FRAGMENT] = "Last Fragment",
}

-- Helper function to determine message type
local function get_message_type(flags)
    local lower_flags = flags & 0x00FF  -- Extract lower 8 bits
    for flag_combo, msg_type in pairs(MESSAGE_TYPES) do
        if lower_flags == flag_combo then
            return msg_type
        end
    end
    -- Check for composite flags that include data flags
    if (lower_flags & FLAG_DATA) ~= 0 then
        if (lower_flags & FLAG_FRAGMENTED) ~= 0 then
            if (lower_flags & FLAG_LAST_FRAGMENT) ~= 0 then
                return "Last Fragment (Data)"
            else
                return "Fragmented Data"
            end
        else
            return "Data"
        end
    end
    -- Default case
    return "Unknown"
end

-- Define color preferences (customizable)
-- These colors are for reference; actual coloring is handled via Wireshark's GUI
local COLORS = {
    SYN = { r = 255, g = 200, b = 200 },          -- Light Red
    SYN_ACK = { r = 255, g = 150, b = 150 },      -- Darker Red
    ACK = { r = 200, g = 255, b = 200 },          -- Light Green
    NACK = { r = 255, g = 255, b = 200 },        -- Light Yellow
    FIN = { r = 200, g = 200, b = 255 },          -- Light Blue
    FIN_ACK = { r = 150, g = 150, b = 255 },      -- Darker Blue
    KeepAlive = { r = 255, g = 255, b = 255 },    -- White
    Data = { r = 200, g = 200, b = 255 },         -- Light Blue
    Fragmented_Data = { r = 255, g = 200, b = 255 }, -- Light Magenta
    Last_Fragment = { r = 255, g = 180, b = 255 },   -- Slightly different Magenta
    Unknown = { r = 200, g = 200, b = 200 },      -- Light Gray
}

-- Dissector function
function custom_udp_proto.dissector(buffer, pinfo, tree)
    -- Ensure buffer has enough length for header and CRC
    if buffer:len() < 2 + 4 + 4 + 2 then
        return
    end

    pinfo.cols.protocol = custom_udp_proto.name

    local subtree = tree:add(custom_udp_proto, buffer(), "Custom UDP Protocol Data")

    -- Parse Flags (2 bytes)
    local flags = buffer(0,2):uint()
    subtree:add(f_flags, buffer(0,2))

    -- Determine message type based on flags
    local msg_type = get_message_type(flags)
    subtree:add(f_message_type, msg_type)

    -- Set the color_field based on message type for coloring rules
    local color_name = ""
    if msg_type == "SYN" then
        color_name = "SYN"
    elseif msg_type == "SYN-ACK" then
        color_name = "SYN-ACK"
    elseif msg_type == "ACK" then
        color_name = "ACK"
    elseif msg_type == "NACK" then
        color_name = "NACK"
    elseif msg_type == "FIN" then
        color_name = "FIN"
    elseif msg_type == "FIN-ACK" then
        color_name = "FIN-ACK"
    elseif msg_type == "KeepAlive" then
        color_name = "KeepAlive"
    elseif msg_type == "Data" then
        color_name = "Data"
    elseif msg_type == "Fragmented Data" then
        color_name = "Fragmented_Data"
    elseif msg_type == "Last Fragment (Data)" then
        color_name = "Last_Fragment"
    else
        color_name = "Unknown"
    end

    subtree:add(f_color_field, color_name)

    -- Parse Fragment Offset (4 bytes)
    subtree:add(f_fragment_offset, buffer(2,4))

    -- Parse ACK Number (4 bytes)
    subtree:add(f_ack_number, buffer(6,4))

    -- Calculate data length: total length minus header (10 bytes: 2 + 4 + 4) and CRC (2 bytes)
    local data_length = buffer:len() - 2 - 4 - 4 - 2
    if data_length < 0 then
        data_length = 0
    end

    -- Parse Data if present
    if data_length > 0 then
        subtree:add(f_data, buffer(10, data_length))
    end

    -- Parse CRC16 Checksum (last 2 bytes)
    subtree:add(f_crc16, buffer(buffer:len()-2,2))

    -- Add a subtree for detailed interpretation
    local details = subtree:add("Details")

    -- Interpret Flags
    local flags_tree = details:add("Flag Details")
    if (flags & FLAG_SYN) ~= 0 then flags_tree:add("SYN") end
    if (flags & FLAG_ACK) ~= 0 then flags_tree:add("ACK") end
    if (flags & FLAG_NACK) ~= 0 then flags_tree:add("NACK") end
    if (flags & FLAG_FIN) ~= 0 then flags_tree:add("FIN") end
    if (flags & FLAG_DATA) ~= 0 then flags_tree:add("DATA") end
    if (flags & FLAG_FRAGMENTED) ~= 0 then flags_tree:add("FRAGMENTED") end
    if (flags & FLAG_LAST_FRAGMENT) ~= 0 then flags_tree:add("LAST_FRAGMENT") end
    if (flags & FLAG_KEEPALIVE) ~= 0 then flags_tree:add("KEEPALIVE") end

    -- Additional interpretation based on message type
    if msg_type == "Data" then
        details:add("Message Type: Text/Data Message")
    elseif msg_type == "Fragmented Data" then
        details:add("Message Type: Fragmented Data")
    elseif msg_type == "Last Fragment (Data)" then
        details:add("Message Type: Last Fragment of Data")
    elseif msg_type == "SYN" then
        details:add("Message Type: Synchronization (SYN) Packet")
    elseif msg_type == "SYN-ACK" then
        details:add("Message Type: Synchronization Acknowledgment (SYN-ACK) Packet")
    elseif msg_type == "ACK" then
        details:add("Message Type: Acknowledgment (ACK) Packet")
    elseif msg_type == "NACK" then
        details:add("Message Type: Negative Acknowledgment (NACK) Packet")
    elseif msg_type == "FIN" then
        details:add("Message Type: Finish (FIN) Packet")
    elseif msg_type == "FIN-ACK" then
        details:add("Message Type: Finish Acknowledgment (FIN-ACK) Packet")
    elseif msg_type == "KeepAlive" then
        details:add("Message Type: KeepAlive Packet")
    else
        details:add("Message Type: " .. msg_type)
    end

    -- Optional: Detailed data interpretation
    if msg_type:find("Data") then
        -- Attempt to decode data as UTF-8 text
        local ok, decoded = pcall(function() return buffer(10, data_length):string() end)
        if ok then
            details:add("Decoded Data: " .. decoded)
        else
            details:add("Decoded Data: [Non-UTF8 Data]")
        end
    elseif msg_type:find("Fragment") then
        details:add("Note: This packet is part of a fragmented message.")
    end

    -- **Packet Coloring Implementation**
    -- The coloring is handled via the 'udp.color_field' which can be used to create coloring rules in Wireshark's GUI.
end

-- Register the dissector for multiple UDP ports
local udp_ports = {55555, 55556}  -- Add your target ports here
local udp_table = DissectorTable.get("udp.port")

for _, port in ipairs(udp_ports) do
    udp_table:add(port, custom_udp_proto)
end
