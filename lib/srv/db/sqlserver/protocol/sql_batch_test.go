package protocol

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSQLBatch(t *testing.T) {
	buff, err := os.ReadFile("/Users/marek/packets/6_pkg.bin")
	require.NoError(t, err)

	fmt.Println(hex.Dump(buff))
	p, err := ReadSQLBatch(bytes.NewReader(buff))
	require.NoError(t, err)
	p = p

}

func TestRPCRequest(t *testing.T) {
	buff, err := os.ReadFile("/Users/marek/packetsrpc/18/0_pkg.bin")
	require.NoError(t, err)

	fmt.Println(hex.Dump(buff))
	p, err := ReadRPCRequest(bytes.NewReader(buff))
	require.NoError(t, err)
	p = p

}
