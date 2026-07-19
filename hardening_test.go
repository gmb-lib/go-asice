package asice

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// buildZip assembles an arbitrary ZIP for shape tests. Each entry is written
// with the given method; content is written as-is.
type zipEntry struct {
	name    string
	content []byte
	method  uint16
}

func buildZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: e.method})
		if err != nil {
			t.Fatalf("create %q: %v", e.name, err)
		}
		if _, err := w.Write(e.content); err != nil {
			t.Fatalf("write %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func sampleContainer(t *testing.T) []byte {
	t.Helper()
	docs := sampleDocs()
	sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{})}
	container, err := BuildContainer(docs, []File{sig}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}
	return container
}

// --- Sniff -------------------------------------------------------------------

func TestSniff_ValidContainer(t *testing.T) {
	if err := Sniff(sampleContainer(t)); err != nil {
		t.Fatalf("Sniff on a built container: %v", err)
	}
}

func TestSniff_Rejections(t *testing.T) {
	valid := sampleContainer(t)

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"not zip at all", []byte("%PDF-1.7 not a zip")},
		{"prefixed junk before a valid zip (polyglot)", append([]byte("<html>junk</html>"), valid...)},
		{"plain zip without mimetype", buildZip(t, []zipEntry{
			{name: "doc.txt", content: []byte("hello"), method: zip.Deflate},
		})},
		{"mimetype not first", buildZip(t, []zipEntry{
			{name: "doc.txt", content: []byte("hello"), method: zip.Deflate},
			{name: "mimetype", content: []byte(MimeType), method: zip.Store},
		})},
		{"mimetype compressed", buildZip(t, []zipEntry{
			{name: "mimetype", content: []byte(MimeType), method: zip.Deflate},
			{name: "doc.txt", content: []byte("hello"), method: zip.Deflate},
		})},
		{"mimetype wrong value", buildZip(t, []zipEntry{
			{name: "mimetype", content: []byte("application/zip"), method: zip.Store},
			{name: "doc.txt", content: []byte("hello"), method: zip.Deflate},
		})},
		{"mimetype overlong value", buildZip(t, []zipEntry{
			{name: "mimetype", content: append([]byte(MimeType), []byte(" and more")...), method: zip.Store},
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Sniff(tc.data)
			if err == nil {
				t.Fatalf("Sniff accepted %s", tc.name)
			}
			if !errors.Is(err, ErrInvalidContainer) {
				t.Fatalf("want ErrInvalidContainer, got %v", err)
			}
		})
	}
}

func TestIsZip(t *testing.T) {
	if !IsZip(sampleContainer(t)) {
		t.Fatal("IsZip false for a built container")
	}
	if IsZip([]byte("%PDF-1.7")) || IsZip(nil) || IsZip([]byte("PK")) {
		t.Fatal("IsZip accepted non-zip bytes")
	}
	// A zip with prefixed junk parses via zip.NewReader but must fail IsZip.
	prefixed := append([]byte("junk"), sampleContainer(t)...)
	if IsZip(prefixed) {
		t.Fatal("IsZip accepted a prefixed (polyglot) archive")
	}
}

// --- decompression limits ------------------------------------------------------

// bombZip builds a zip whose single signature-named entry inflates to n bytes
// of zeros (highly compressible — a miniature decompression bomb).
func bombZip(t *testing.T, entryName string, n int) []byte {
	t.Helper()
	return buildZip(t, []zipEntry{
		{name: "mimetype", content: []byte(MimeType), method: zip.Store},
		{name: entryName, content: bytes.Repeat([]byte{0}, n), method: zip.Deflate},
	})
}

func TestLimits_EntryCapTripsWhileReading(t *testing.T) {
	// 1 MiB of zeros compresses to ~1 KiB; the header may even claim any size —
	// the cap must trip on decompressed output, not on declared sizes.
	bomb := bombZip(t, "META-INF/signatures0.xml", 1<<20)
	_, _, _, err := Inspect(bomb, WithLimits(Limits{MaxEntryBytes: 1 << 10}))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestLimits_TotalBudgetAcrossEntries(t *testing.T) {
	// Two entries, each under the per-entry cap, together over the total.
	docs := []File{
		{Name: "a.bin", Data: bytes.Repeat([]byte{0}, 700)},
		{Name: "b.bin", Data: bytes.Repeat([]byte{0}, 700)},
	}
	sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{})}
	container, err := BuildContainer(docs, []File{sig}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}
	_, err = DataObjects(container, WithLimits(Limits{MaxEntryBytes: 1 << 10, MaxTotalBytes: 1 << 10}))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge across the total budget, got %v", err)
	}
	// The same container reads fine under the defaults.
	if _, err := DataObjects(container); err != nil {
		t.Fatalf("DataObjects under defaults: %v", err)
	}
}

func TestLimits_EntryCount(t *testing.T) {
	entries := []zipEntry{{name: "mimetype", content: []byte(MimeType), method: zip.Store}}
	for i := 0; i < 20; i++ {
		entries = append(entries, zipEntry{name: fmt.Sprintf("f%d.txt", i), content: []byte("x"), method: zip.Deflate})
	}
	z := buildZip(t, entries)
	if err := Sniff(z, WithLimits(Limits{MaxEntries: 5})); !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("want ErrTooManyEntries, got %v", err)
	}
	if err := Sniff(z); err != nil {
		t.Fatalf("Sniff under defaults: %v", err)
	}
}

func TestLimits_NonPositiveFieldsKeepDefaults(t *testing.T) {
	eff := effectiveLimits([]Option{WithLimits(Limits{MaxEntryBytes: 1})})
	if eff.MaxEntryBytes != 1 {
		t.Fatalf("MaxEntryBytes not overridden: %d", eff.MaxEntryBytes)
	}
	if eff.MaxTotalBytes != DefaultLimits.MaxTotalBytes || eff.MaxEntries != DefaultLimits.MaxEntries {
		t.Fatalf("unset fields lost their defaults: %+v", eff)
	}
}

func TestLimits_ExistingAPIUnchangedUnderDefaults(t *testing.T) {
	// The variadic options must not change behavior for existing callers: a
	// normal container round-trips through every reader without options.
	container := sampleContainer(t)
	if _, _, _, err := Inspect(container); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if _, err := DataObjects(container); err != nil {
		t.Fatalf("DataObjects: %v", err)
	}
	if _, err := ExtractSignatures(container); err != nil {
		t.Fatalf("ExtractSignatures: %v", err)
	}
}

// --- fuzz ---------------------------------------------------------------------

// FuzzSniff and FuzzInspect assert the untrusted-input invariants: never
// panic, and never read unbounded amounts (tight limits keep fuzz fast).
func FuzzSniff(f *testing.F) {
	f.Add([]byte("PK\x03\x04 garbage"))
	f.Add([]byte("%PDF-1.7"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Sniff(data, WithLimits(Limits{MaxEntryBytes: 1 << 16, MaxTotalBytes: 1 << 18, MaxEntries: 64}))
	})
}

func FuzzInspect(f *testing.F) {
	f.Add([]byte("PK\x03\x04 garbage"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = Inspect(data, WithLimits(Limits{MaxEntryBytes: 1 << 16, MaxTotalBytes: 1 << 18, MaxEntries: 64}))
	})
}
