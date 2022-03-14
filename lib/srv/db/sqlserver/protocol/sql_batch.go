package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	mssql "github.com/denisenkom/go-mssqldb"
	"github.com/gravitational/trace"
)

type SQLBatch struct {
	packet  Packet
	SQLText string
}
type pp struct {
	Length  uint32
	SQLText string
}

func ReadSQLBatch(r io.Reader) (*SQLBatch, error) {
	pkt, err := ReadPacket(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if pkt.Type != PacketTypeSQLBatch {
		return nil, trace.BadParameter("expected SQLBatch packet, got: %#v", pkt)
	}

	var headersLength uint32
	if err := binary.Read(bytes.NewReader(pkt.Data), binary.LittleEndian, &headersLength); err != nil {
		return nil, trace.Wrap(err)
	}

	fmt.Println(hex.Dump(pkt.Data[:]))

	s, err := mssql.ParseUCS2String(pkt.Data[headersLength:])
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &SQLBatch{
		packet:  *pkt,
		SQLText: s,
	}, nil
}

type RPCRequest struct {
	packet Packet
}

type ff struct {
	idswitch uint16
	procID   uint16
}

func ReadRPCRequest(r io.Reader) (*RPCRequest, error) {
	pkt, err := ReadPacket(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if pkt.Type != PacketTypeRPCRequest {
		return nil, trace.BadParameter("expected SQLBatch packet, got: %#v", pkt)
	}

	var headersLength uint32
	if err := binary.Read(bytes.NewReader(pkt.Data), binary.LittleEndian, &headersLength); err != nil {
		return nil, trace.Wrap(err)
	}

	fmt.Println(hex.Dump(pkt.Data[:]))
	fmt.Println(hex.Dump(pkt.Data[headersLength:]))

	var idswitch uint16
	rr := bytes.NewReader(pkt.Data[headersLength:])
	if err := binary.Read(rr, binary.LittleEndian, &idswitch); err != nil {
		return nil, trace.Wrap(err)
	}
	var procID uint16
	if err := binary.Read(rr, binary.LittleEndian, &procID); err != nil {
		return nil, trace.Wrap(err)
	}

	var flags uint16
	if err := binary.Read(rr, binary.LittleEndian, &flags); err != nil {
		return nil, trace.Wrap(err)
	}
	b, err := rr.ReadByte()
	b, err = rr.ReadByte()
	b, err = rr.ReadByte()
	b, err = rr.ReadByte()
	b, err = rr.ReadByte()
	b, err = rr.ReadByte()
	b, err = rr.ReadByte()
	b, err = rr.ReadByte()
	b, err = rr.ReadByte()
	b, err = rr.ReadByte()
	//b, err = rr.ReadByte()
	ss, err := readBVarChar(rr)
	if err != nil {
		err = err
	}
	b = b
	ss = ss

	return &RPCRequest{
		packet: *pkt,
	}, nil
}

func readBVarChar(r io.Reader) (res string, err error) {
	var b [1]byte
	numchars, err := r.Read(b[:])
	if err != nil {
		return "", err
	}

	// A zero length could be returned, return an empty string
	if numchars == 0 {
		return "", nil
	}
	return readUcs2(r, int(b[0]))
}

func readUcs2(r io.Reader, numchars int) (res string, err error) {
	buf := make([]byte, numchars*2)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return "", err
	}
	return mssql.ParseUCS2String(buf)
}
