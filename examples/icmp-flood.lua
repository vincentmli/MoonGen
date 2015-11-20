local dpdk		= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local utils 	= require "utils"
local stats             = require "stats"

local arp		= require "proto.arp"
local ip		= require "proto.ip4"
local icmp		= require "proto.icmp"


function master(txPorts, minIp, numIps, rate)
        if not txPorts then
                printf("usage: txPort1[,txPort2[,...]] [minIP numIPs rate]")
                return
        end
        txPorts = tostring(txPorts)
        minIp = minIp or "10.0.0.1"
        numIps = numIps or 100
        rate = rate or 0
        for currentTxPort in txPorts:gmatch("(%d+),?") do
                currentTxPort = tonumber(currentTxPort)
                local txDev = device.config({ port = currentTxPort })
                txDev:wait()
                txDev:getTxQueue(0):setRate(rate)
                dpdk.launchLua("loadSlave", currentTxPort, 0, minIp, numIps)
        end
        dpdk.waitForSlaves()
end


function loadSlave(port, queue, minA, numIPs)
        --- parse and check ip addresses

        local minIP, ipv4 = parseIPAddress(minA)
        if minIP then
                printf("INFO: Detected an %s address.", minIP and "IPv4" or "IPv6")
        else
                errorf("ERROR: Invalid minIP: %s", minA)
        end

        -- min TCP packet size for IPv6 is 74 bytes (+ CRC)
        local packetLen = ipv4 and 60 or 74

        --continue normally
        local queue = device.get(port):getTxQueue(queue)
        local mem = memory.createMemPool(function(buf)
                buf:getIcmpPacket(ipv4):fill{
                        ethSrc="a0:36:9f:a1:4d:6d", ethDst="52:54:00:2E:62:A2",
                        --- ip4Dst="10.9.1.2",
                        ip4Dst="10.9.3.1",
			icmpType=8, 
                        pktLength=packetLen }
        end)

        local lastPrint = dpdk.getTime()
        local totalSent = 0
        local lastTotal = 0
        local lastSent = 0
        local bufs = mem:bufArray(128)
        local counter = 0
        local c = 0

        local txStats = stats:newDevTxCounter(queue, "plain")
        while dpdk.running() do
                -- faill packets and set their size
                bufs:alloc(packetLen)
                for i, buf in ipairs(bufs) do
                        local pkt = buf:getIcmpPacket(ipv4)

                        --increment IP
                        if ipv4 then
                                pkt.ip4.src:set(minIP)
				--pkt.icmp:setType(icmp.ECHO_REQUEST.type)
                                pkt.ip4.src:add(counter)
                        else
                                pkt.ip6.src:set(minIP)
                                pkt.ip6.src:add(counter)
                        end

                        counter = incAndWrap(counter, numIPs)
			pkt.ip4:setChecksum(0)
			pkt.icmp:calculateChecksum(pkt.ip4:getLength() - pkt.ip4:getHeaderLength() * 4)
--			pkt.icmp.body.uint16[0] = math.random(0, 2^16 - 1)
--			pkt.icmp.body.uint16[1] = math.random(0, 2^16 - 1)

                        -- dump first 3 packets
                        if c < 3 then
                                buf:dump()
                                c = c + 1
                        end
                end
                --offload checksums to NIC
		
                bufs:offloadIPChecksums(ipv4)

                totalSent = totalSent + queue:send(bufs)
                txStats:update()
        end
        txStats:finalize()
end


