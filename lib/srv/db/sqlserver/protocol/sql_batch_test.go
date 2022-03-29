package protocol

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSQLBatchWalk(t *testing.T) {
	filepath.WalkDir("/Users/marek/packets", func(path string, d fs.DirEntry, err error) error {
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

		p, err := ReadSQLBatch(bytes.NewReader(buff))
		require.NoError(t, err)
		require.NotEmpty(t, p.SQLText)
		t.Log(d.Name())
		t.Log(p.SQLText)
		return nil
	})
}

func TestRPCRequestWalk(t *testing.T) {
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
