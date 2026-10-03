/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package provisioning

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestRenderBoxWithStyleKeepsNonTTYOutputPlain(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdout := os.Stdout
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = originalStdout
		_ = writer.Close()
		_ = reader.Close()
	})

	renderBoxWithStyle("status", []string{"saved"}, 12, func(line string) string {
		return color(line, colorGreen)
	})
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = originalStdout

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), "\033[") {
		t.Fatalf("non-TTY output contains ANSI colour codes: %q", output)
	}
	if !strings.Contains(string(output), "saved") {
		t.Fatalf("rendered output does not contain the status text: %q", output)
	}
}
