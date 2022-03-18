package protocol

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

//func TestRPCRequest(t *testing.T) {
//	buff, err := os.ReadFile("/Users/marek/packetsrpc/18/0_pkg.bin")
//	require.NoError(t, err)
//
//	fmt.Println(hex.Dump(buff))
//	p, err := ReadRPCRequest(bytes.NewReader(buff))
//	require.NoError(t, err)
//	p = p
//
//}

func TestRPCRequest2(t *testing.T) {
	filepath.WalkDir("/Users/marek/packetsrpc/", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_pkg.bin") {
			return nil

		}
		buff, err := os.ReadFile(path)
		require.NoError(t, err)

		p, err := ReadRPCRequest2(bytes.NewReader(buff))
		require.NoError(t, err)
		require.NotEmpty(t, p.Query)
		t.Log(d.Name())
		t.Log(p.Query)
		return nil
	})
}

func TestFoo(t *testing.T) {
	var buff bytes.Buffer
	buff.Write([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	err := writeBVarChar(&buff, "select @@version")
	require.NoError(t, err)

	fmt.Println(hex.Dump(buff.Bytes()))

}
