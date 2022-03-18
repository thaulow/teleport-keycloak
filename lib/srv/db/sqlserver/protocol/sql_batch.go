package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"unicode/utf16"

	mssql "github.com/denisenkom/go-mssqldb"
	"github.com/gravitational/trace"
)

type SQLBatch struct {
	*Packet
	SQLText string
}
type pp struct {
	Length  uint32
	SQLText string
}

func ToSQLBatch(p *Packet) (*SQLBatch, error) {
	if p.Type != PacketTypeSQLBatch {
		return nil, trace.BadParameter("expected SQLBatch packet, got: %#v", p.Type)
	}

	var headersLength uint32
	if err := binary.Read(bytes.NewReader(p.Data), binary.LittleEndian, &headersLength); err != nil {
		return nil, trace.Wrap(err)
	}

	fmt.Println(hex.Dump(p.Data[:]))

	s, err := mssql.ParseUCS2String(p.Data[headersLength:])
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &SQLBatch{
		Packet:  p,
		SQLText: s,
	}, nil
}

func ToRPCRequest(p *Packet) (*RPCRequest, error) {
	if p.Type != PacketTypeRPCRequest {
		return nil, trace.BadParameter("expected SQLBatch packet, got: %#v", p.Type)
	}

	var headersLength uint32
	if err := binary.Read(bytes.NewReader(p.Data), binary.LittleEndian, &headersLength); err != nil {
		return nil, trace.Wrap(err)
	}

	kk := p.Data[headersLength+2:]
	rr := bytes.NewReader(kk)

	var rpcContent RPCContent
	if err := binary.Read(rr, binary.LittleEndian, &rpcContent); err != nil {
		return nil, trace.Wrap(err)
	}

	var ti typeInfo
	if err := binary.Read(rr, binary.LittleEndian, &ti); err != nil {
		return nil, trace.Wrap(err)
	}
	pp, err := readBVarChar(rr)
	if err != nil {
		panic(err)
	}

	return &RPCRequest{
		Packet: p,
		Query:  pp,
	}, nil
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
		Packet:  pkt,
		SQLText: s,
	}, nil
}

type RPCRequest struct {
	*Packet
	Query string
}

type ff struct {
	idswitch uint16
	procID   uint16
}

//func ReadRPCRequest(r io.Reader) (*RPCRequest, error) {
//	pkt, err := ReadPacket(r)
//	if err != nil {
//		return nil, trace.Wrap(err)
//	}
//
//	if pkt.Type != PacketTypeRPCRequest {
//		return nil, trace.BadParameter("expected SQLBatch packet, got: %#v", pkt)
//	}
//
//	var headersLength uint32
//	if err := binary.Read(bytes.NewReader(pkt.Data), binary.LittleEndian, &headersLength); err != nil {
//		return nil, trace.Wrap(err)
//	}
//
//	var idswitch uint16
//	rr := bytes.NewBuffer(pkt.Data[headersLength+2:])
//	if err != nil {
//		panic(err)
//	}
//
//	var kk [2]byte
//	rr.Read(kk[:])
//
//	fmt.Println(hex.Dump(kk[:]))
//
//	if err := binary.Read(bytes.NewReader(kk[:]), binary.LittleEndian, &idswitch); err != nil {
//		return nil, trace.Wrap(err)
//	}
//
//	var flags uint16
//	if err := binary.Read(rr, binary.LittleEndian, &flags); err != nil {
//		return nil, trace.Wrap(err)
//	}
//
//	var nameLength uint8
//	if err := binary.Read(rr, binary.LittleEndian, &nameLength); err != nil {
//		return nil, trace.Wrap(err)
//	}
//	nameLength = nameLength
//
//	var flagsParam uint8
//	if err := binary.Read(rr, binary.LittleEndian, &flagsParam); err != nil {
//		return nil, trace.Wrap(err)
//	}
//	flagsParam = flagsParam
//
//	var ti typeInfo
//	if err := binary.Read(rr, binary.LittleEndian, &ti); err != nil {
//		return nil, trace.Wrap(err)
//	}
//
//	pp, err := readBVarChar(rr)
//	if err != nil {
//		panic(err)
//	}
//	pp = pp
//
//	return &RPCRequest{
//		packet: *pkt,
//	}, nil
//}

type Collation struct {
	LcidAndFlags uint32
	SortId       uint8
}

type typeInfo struct {
	NameLength  uint8
	FlagsParam  uint8
	T           uint8
	MaxLength   uint16
	Collocation uint32
	SortID      uint8
}

func writeBVarChar(w io.Writer, s string) (err error) {
	buf := str2ucs2(s)
	var numchars int = len(buf) / 2
	if numchars > 0xff {
		panic("invalid size for B_VARCHAR")
	}
	err = binary.Write(w, binary.LittleEndian, uint8(numchars))
	if err != nil {
		return
	}
	_, err = w.Write(buf)
	return
}

func readBVarChar(r io.Reader) (res string, err error) {
	var numchars uint16
	if err := binary.Read(r, binary.LittleEndian, &numchars); err != nil {
		return "", err
	}
	if numchars == 0 {
		return "", nil
	}
	return readUcs2(r, int(numchars))
}

func str2ucs2(s string) []byte {
	res := utf16.Encode([]rune(s))
	ucs2 := make([]byte, 2*len(res))
	for i := 0; i < len(res); i++ {
		ucs2[2*i] = byte(res[i])
		ucs2[2*i+1] = byte(res[i] >> 8)
	}
	return ucs2
}

func readUcs2(r io.Reader, numchars int) (res string, err error) {
	buf := make([]byte, numchars)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return "", err
	}
	return mssql.ParseUCS2String(buf)
}

type RPCContent struct {
	IDSwitch uint16
	Flags    uint16
}

func ReadRPCRequest2(r io.Reader) (*RPCRequest, error) {
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

	kk := pkt.Data[headersLength+2:]
	rr := bytes.NewReader(kk)
	if err != nil {
		panic(err)
	}

	var rpcContent RPCContent
	if err := binary.Read(rr, binary.LittleEndian, &rpcContent); err != nil {
		return nil, trace.Wrap(err)
	}

	var ti typeInfo
	if err := binary.Read(rr, binary.LittleEndian, &ti); err != nil {
		return nil, trace.Wrap(err)
	}
	pp, err := readBVarChar(rr)
	if err != nil {
		panic(err)
	}

	return &RPCRequest{
		Packet: pkt,
		Query:  pp,
	}, nil
}

type tdsReader struct {
	*bytes.Reader
}

func (t tdsReader) byte() byte {
	b, err := t.ReadByte()
	if err != nil {
		panic(err)
	}
	return b
}

func newTdsReader(buff []byte) *tdsReader {
	return &tdsReader{
		Reader: bytes.NewReader(buff),
	}
}

const (
	typeNull     = 0x1f
	typeInt1     = 0x30
	typeBit      = 0x32
	typeInt2     = 0x34
	typeInt4     = 0x38
	typeDateTim4 = 0x3a
	typeFlt4     = 0x3b
	typeMoney    = 0x3c
	typeDateTime = 0x3d
	typeFlt8     = 0x3e
	typeMoney4   = 0x7a
	typeInt8     = 0x7f
)

func readTypeInfo(r *tdsReader) (interface{}, error) {
	TypeId, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch TypeId {
	case typeNull, typeInt1, typeBit, typeInt2, typeInt4, typeDateTim4,
		typeFlt4, typeMoney, typeDateTime, typeFlt8, typeMoney4, typeInt8:
		size := 0
		switch TypeId {
		case typeNull:
			size = 0
		case typeInt1, typeBit:
			size = 1
		case typeInt2:
			size = 2
		case typeInt4, typeDateTim4, typeFlt4, typeMoney4:
			size = 4
		case typeMoney, typeDateTime, typeFlt8, typeInt8:
			size = 8
		default:
			panic("unknow type")
		}
		buff := make([]byte, size)
		_, err := r.Read(buff)
		if err != nil {
			panic(err)
		}

		return readFixedType(TypeId, buff), nil
	default:
		//readVarLen(TypeId, r)
	}
	panic("fdafsa")
}
func readFixedType(typeID uint8, buf []byte) interface{} {
	switch typeID {
	case typeNull:
		return nil
	case typeInt1:
		return int64(buf[0])
	case typeBit:
		return buf[0] != 0
	case typeInt2:
		return int64(int16(binary.LittleEndian.Uint16(buf)))
	case typeInt4:
		return int64(int32(binary.LittleEndian.Uint32(buf)))
	//case typeDateTim4:
	//	return decodeDateTim4(buf)
	//case typeFlt4:
	//	return math.Float32frombits(binary.LittleEndian.Uint32(buf))
	//case typeMoney4:
	//	return decodeMoney4(buf)
	//case typeMoney:
	//	return decodeMoney(buf)
	//case typeDateTime:
	//	return decodeDateTime(buf)
	//case typeFlt8:
	//	return math.Float64frombits(binary.LittleEndian.Uint64(buf))
	case typeInt8:
		return int64(binary.LittleEndian.Uint64(buf))
	default:
		panic("Invalid typeid")
	}
	panic("shoulnd't get here")
}

// variable-length data types
// http://msdn.microsoft.com/en-us/library/dd358341.aspx
const (
	// byte len types
	typeGuid            = 0x24
	typeIntN            = 0x26
	typeDecimal         = 0x37 // legacy
	typeNumeric         = 0x3f // legacy
	typeBitN            = 0x68
	typeDecimalN        = 0x6a
	typeNumericN        = 0x6c
	typeFltN            = 0x6d
	typeMoneyN          = 0x6e
	typeDateTimeN       = 0x6f
	typeDateN           = 0x28
	typeTimeN           = 0x29
	typeDateTime2N      = 0x2a
	typeDateTimeOffsetN = 0x2b
	typeChar            = 0x2f // legacy
	typeVarChar         = 0x27 // legacy
	typeBinary          = 0x2d // legacy
	typeVarBinary       = 0x25 // legacy

	// short length types
	typeBigVarBin  = 0xa5
	typeBigVarChar = 0xa7
	typeBigBinary  = 0xad
	typeBigChar    = 0xaf
	typeNVarChar   = 0xe7
	typeNChar      = 0xef
	typeXml        = 0xf1
	typeUdt        = 0xf0
	typeTvp        = 0xf3

	// long length types
	typeText    = 0x23
	typeImage   = 0x22
	typeNText   = 0x63
	typeVariant = 0x62
)

//func readVarLen(typeID byte, r *tdsReader) {
//	switch typeID {
//	case typeGuid, typeIntN, typeDecimal, typeNumeric,
//		typeBitN, typeDecimalN, typeNumericN, typeFltN,
//		typeMoneyN, typeDateTimeN, typeChar,
//		typeVarChar, typeBinary, typeVarBinary:
//		// byte len types
//		ti.Size = int(r.byte())
//		ti.Buffer = make([]byte, ti.Size)
//		switch ti.TypeId {
//		case typeDecimal, typeNumeric, typeDecimalN, typeNumericN:
//			//ti.Prec = r.byte()
//			//ti.Scale = r.byte()
//			r.byte()
//			r.byte()
//		}
//		ti.Reader = readByteLenType
//	default:
//		panic("Invalid type %d")
//	}
//}
