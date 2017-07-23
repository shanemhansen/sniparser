package sniparser

import (
	"errors"
	"fmt"
	"io"
	"net"
)

// ReadServerName will read the client hello from rdr, returning bytes read
// and the server name
func ReadServerName(rdr io.Reader) (net.Buffers, string, error) {
	var buffers net.Buffers
	// step 1: parse out a valid TLS record, and ensure
	const handshakeType = 22
	const recordHeaderLen = 5
	buf := make([]byte, recordHeaderLen)
	if _, err := io.ReadFull(rdr, buf); err != nil {
		return nil, "", err
	}
	buffers = append(buffers, buf)
	typ := buf[0]
	if typ == 0x80 { // check for likely SSLv2 connection attempt
		return nil, "", errors.New("unsupported SSLv2 handshake received")
	}
	if typ != handshakeType {
		return nil, "", fmt.Errorf("first byte does not look like a TLS handshake. %x", typ)
	}
	// that the TLS version supports SNI
	vers := uint16(buf[1])<<8 | uint16(buf[2])
	if vers >= 0x1000 { // This is really major=16 minor=00
		return nil, "", fmt.Errorf("unsupported TLS version, seems way too big: %x", vers)
	}
	recordLength := int(buf[3])<<8 | int(buf[4])
	// hey, we've consumed all 5 bytes
	if recordLength > 0xFFFF {
		return nil, "", fmt.Errorf("record length too large: %d, max is 0xFFFF (65k)", recordLength)
	}
	// read recordLength bytes
	buf = make([]byte, recordLength)
	if _, err := io.ReadFull(rdr, buf); err != nil {
		return nil, "", err
	}
	buffers = append(buffers, buf)

	// step 2: parse the actual record into client hello
	if len(buf) < 42 {
		return nil, "", errors.New("not enough data for valid client hello")
	}
	// skip over everything we can
	sessionIdLen := int(buf[38])
	if sessionIdLen > 32 || len(buf) < 39+sessionIdLen {
		return nil, "", errors.New("buffer not big enough for session id")
	}
	// skip over session id
	buf = buf[39+sessionIdLen:]
	if len(buf) < 2 {
		return nil, "", errors.New("not enough bytes for cipher suite length")
	}
	cipherSuiteLen := int(buf[0])<<8 | int(buf[1])
	if cipherSuiteLen%2 == 1 || len(buf) < 2+cipherSuiteLen {
		return nil, "", errors.New("cipher suite length was odd, or buffer was too small to read cipherSuiteLen bytes")
	}
	buf = buf[2+cipherSuiteLen:]
	if len(buf) < 1 {
		return nil, "", errors.New("couldn't read compression methods length")
	}
	compressionMethodsLen := int(buf[0])
	if len(buf) < 1+compressionMethodsLen {
		return nil, "", errors.New("buf not big enough to read compression methods")
	}
	buf = buf[1+compressionMethodsLen:]
	if len(buf) == 0 {
		// ClientHello is optionally followed by extension data
		return nil, "", nil
	}
	if len(buf) < 2 {
		return nil, "", errors.New("Couldn't read extension length field.")
	}
	extensionsLength := int(buf[0])<<8 | int(buf[1])
	buf = buf[2:]
	if extensionsLength != len(buf) {
		return nil, "", errors.New("Wrong number of remaining bytes in client hello")
	}
	var extensionBytes []byte
	var err error
	var extensionID uint16
	for len(buf) != 0 {
		extensionBytes, buf, extensionID, err = nextExtension(buf)
		if err != nil {
			return nil, "", err
		}
		const sniExtension = 0x0000
		if extensionID == sniExtension {
			break
		}

	}
	// step 3: parse the extensions and find servername and
	// extract it
	hostname, err := parseSNIExtention(extensionBytes)
	if err != nil {
		return nil, hostname, err
	}
	return buffers, hostname, err
}

func nextExtension(input []byte) (extensionBytes, data []byte, extensionID uint16, err error) {
	data = input
	if len(data) < 4 {
		err = errors.New("not enough data")
		return
	}
	extensionID = uint16(data[0])<<8 | uint16(data[1])
	length := int(data[2])<<8 | int(data[3])
	data = data[4:]
	if len(data) < length {
		err = errors.New("not enough bytes to read extensionLen bytes")
		return
	}
	extensionBytes = data[:length]
	data = data[length:]
	return
}

func parseSNIExtention(extensionBytes []byte) (string, error) {
	// so at this point we know we have a SNI extension.
	if len(extensionBytes) < 2 {
		return "", errors.New("Can't read length of SNI extension")
	}
	namesLen := int(extensionBytes[0])<<8 | int(extensionBytes[1])
	extensionBytes = extensionBytes[2:]
	if len(extensionBytes) != namesLen {
		return "", errors.New("not enough data to read namesLen bytes")
	}
	for len(extensionBytes) > 0 {
		if len(extensionBytes) < 3 {
			return "", errors.New("not enough bytes to read nameType and nameLength")
		}
		nameType := extensionBytes[0]
		nameLen := int(extensionBytes[1])<<8 | int(extensionBytes[2])
		extensionBytes = extensionBytes[3:]
		if len(extensionBytes) < nameLen {
			return "", errors.New("Not enough bytes to read nameLength bytes")
		}
		const serverNameTypeHostName = 0
		if nameType == serverNameTypeHostName {
			return string(extensionBytes[:nameLen]), nil
		}
	}
	return "", errors.New("Couldn't find host name value in server name extension")
}
