package socks5hs

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
)

const (
	VERSION = byte(5)

	METHOD_NOT_REQUIRED  = byte(0)
	METHOD_NO_ACCEPTABLE = byte(0xff)

	RESERVED = byte(0)

	ADDR_TYPE_IP     = byte(1)
	ADDR_TYPE_IPV6   = byte(4)
	ADDR_TYPE_DOMAIN = byte(3)

	CMD_CONNECT       = byte(1)
	CMD_BIND          = byte(2)
	CMD_UDP_ASSOCIATE = byte(3)

	REP_SUCCEED                    = byte(0)
	REP_SERVER_FAILURE             = byte(1)
	REP_CONNECTION_NOT_ALLOW       = byte(2)
	REP_NETWORK_UNREACHABLE        = byte(3)
	REP_HOST_UNREACHABLE           = byte(4)
	REP_CONNECTION_REFUSED         = byte(5)
	REP_TTL_EXPIRED                = byte(6)
	REP_COMMAND_NOT_SUPPORTED      = byte(7)
	REP_ADDRESS_TYPE_NOT_SUPPORTED = byte(8)
)

func Handshake(conn net.Conn) (hostPort string, err error) {
	defer ct(&err)
	read := func(v interface{}) {
		ce(binary.Read(conn, binary.BigEndian, v), "read")
	}
	write := func(v interface{}) {
		ce(binary.Write(conn, binary.BigEndian, v), "read")
	}
	writeAck := func(reply byte) {
		write(VERSION)
		write(reply)
		write(RESERVED)
		write(ADDR_TYPE_IP)
		write([4]byte{0, 0, 0, 0})
		write(uint16(0))
	}

	// handshake
	var ver, nMethods byte
	read(&ver)
	read(&nMethods)
	methods := make([]byte, nMethods)
	read(methods)
	write(VERSION)
	if ver != VERSION || nMethods < byte(1) {
		write(METHOD_NO_ACCEPTABLE)
	} else {
		if bytes.IndexByte(methods, METHOD_NOT_REQUIRED) == -1 {
			write(METHOD_NO_ACCEPTABLE)
		} else {
			write(METHOD_NOT_REQUIRED)
		}
	}

	// request
	var cmd, reserved, addrType byte
	read(&ver)
	read(&cmd)
	read(&reserved)
	read(&addrType)
	if ver != VERSION {
		return "", me(nil, "invalid version")
	}
	if reserved != RESERVED {
		return "", me(nil, "invalid reserved byte")
	}
	if addrType != ADDR_TYPE_IP && addrType != ADDR_TYPE_DOMAIN && addrType != ADDR_TYPE_IPV6 {
		writeAck(REP_ADDRESS_TYPE_NOT_SUPPORTED)
		return "", me(nil, "address type not supported")
	}

	var address []byte
	if addrType == ADDR_TYPE_IP {
		address = make([]byte, 4)
	} else if addrType == ADDR_TYPE_DOMAIN {
		var domainLength byte
		read(&domainLength)
		address = make([]byte, domainLength)
	} else if addrType == ADDR_TYPE_IPV6 {
		address = make([]byte, 16)
	}
	read(address)
	var port uint16
	read(&port)

	if addrType == ADDR_TYPE_IP || addrType == ADDR_TYPE_IPV6 {
		ip := net.IP(address)
		hostPort = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	} else if addrType == ADDR_TYPE_DOMAIN {
		hostPort = net.JoinHostPort(string(address), strconv.Itoa(int(port)))
	}

	if cmd != CMD_CONNECT {
		writeAck(REP_COMMAND_NOT_SUPPORTED)
		return "", me(nil, "command not supported")
	}
	writeAck(REP_SUCCEED)

	return
}
