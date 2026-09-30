// Package compress provides PKS family packed format support.
package compress

import (
	"bytes"
	"testing"
)

// TestParsePKSHeaderAllVariants verifies every signature (standard, underscan
// and overscan) is parsed with the right flags, palette field and data offset.
func TestParsePKSHeaderAllVariants(t *testing.T) {
	palette := make([]byte, 17)
	for i := range palette {
		palette[i] = byte(i + 1)
	}

	cases := []struct {
		name         string
		sig          string
		withPal      bool
		wantVariant  PKSVariant
		wantPlus     bool
		wantOverscan bool
	}{
		{"PKSL standard", "PKSL", true, PKSL, false, false},
		{"PKS3 mode 3", "PKS3", false, PKS3, false, false},
		{"PKSP Plus", "PKSP", false, PKSP, true, false},
		{"PKVL overscan", "PKVL", false, PKVL, false, true},
		{"PKVP overscan Plus", "PKVP", false, PKVP, true, true},
		{"PKUL underscan", "PKUL", true, PKUL, false, false},
		{"PKU3 underscan mode 3", "PKU3", false, PKU3, false, false},
		{"PKUP underscan Plus", "PKUP", true, PKUP, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := []byte(tc.sig)
			if tc.withPal {
				buf = append(buf, palette...)
			}
			buf = append(buf, 0xAA, 0xBB)

			h, err := ParsePKSHeader(buf)
			if err != nil {
				t.Fatalf("ParsePKSHeader(%s) failed: %v", tc.sig, err)
			}
			if h.Variant != tc.wantVariant {
				t.Errorf("variant = %v, want %v", h.Variant, tc.wantVariant)
			}
			if h.CpcPlus != tc.wantPlus {
				t.Errorf("CpcPlus = %v, want %v", h.CpcPlus, tc.wantPlus)
			}
			if h.Overscan != tc.wantOverscan {
				t.Errorf("Overscan = %v, want %v", h.Overscan, tc.wantOverscan)
			}
			if h.Variant.HasPalette() != tc.withPal {
				t.Errorf("HasPalette() = %v, want %v", h.Variant.HasPalette(), tc.withPal)
			}
			wantOffset := 4
			if tc.withPal {
				wantOffset = 21
			}
			if h.DataOffset != wantOffset {
				t.Errorf("DataOffset = %d, want %d", h.DataOffset, wantOffset)
			}
			if tc.withPal && !bytes.Equal(h.Palette[:], palette) {
				t.Errorf("palette = % x, want % x", h.Palette[:], palette)
			}
		})
	}
}

// TestPackPKSVariantRoundTrip packs and depacks each variant: the signature must
// survive, the palette field must be written only for the variants that define
// it, and the payload must come back byte-for-byte.
func TestPackPKSVariantRoundTrip(t *testing.T) {
	payload := make([]byte, 12288) // one underscan pixel payload
	for i := range payload {
		payload[i] = byte(i*11 + 5)
	}
	palette := make([]byte, 17)
	for i := range palette {
		palette[i] = byte(i)
	}

	for _, tc := range []struct {
		name    string
		variant PKSVariant
	}{
		{"PKSL", PKSL}, {"PKS3", PKS3}, {"PKSP", PKSP},
		{"PKVL", PKVL}, {"PKVP", PKVP},
		{"PKUL", PKUL}, {"PKU3", PKU3}, {"PKUP", PKUP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, len(payload)*2+1024)
			n, err := NewPKS().PackPKS(payload, len(payload), buf, tc.variant, palette)
			if err != nil {
				t.Fatalf("PackPKS(%s) failed: %v", tc.name, err)
			}
			packed := buf[:n]

			h, err := ParsePKSHeader(packed)
			if err != nil {
				t.Fatalf("ParsePKSHeader failed: %v", err)
			}
			if h.Variant != tc.variant {
				t.Errorf("packed variant = %v, want %v", h.Variant, tc.variant)
			}
			if tc.variant.HasPalette() && !bytes.Equal(h.Palette[:], palette) {
				t.Errorf("packed palette = % x, want % x", h.Palette[:], palette)
			}

			out := make([]byte, len(payload)+1024)
			dn, dh, err := NewPKS().DepackPKS(packed, out)
			if err != nil {
				t.Fatalf("DepackPKS failed: %v", err)
			}
			if dh.Variant != tc.variant {
				t.Errorf("depacked variant = %v, want %v", dh.Variant, tc.variant)
			}
			if dn != len(payload) || !bytes.Equal(out[:dn], payload) {
				t.Errorf("payload mismatch: got %d bytes, want %d", dn, len(payload))
			}
		})
	}
}

// TestCompressorUnderscanMethods verifies the compressor method constants map to
// the underscan signatures for both packing and depacking.
func TestCompressorUnderscanMethods(t *testing.T) {
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i * 3)
	}

	for _, tc := range []struct {
		name   string
		method PackMethod
		want   string
	}{
		{"MethodPKUL", MethodPKUL, "PKUL"},
		{"MethodPKU3", MethodPKU3, "PKU3"},
		{"MethodPKUP", MethodPKUP, "PKUP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, len(payload)*2+1024)
			n, err := NewCompressor().Pack(payload, len(payload), buf, 0, tc.method)
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}
			if got := string(buf[:4]); got != tc.want {
				t.Errorf("signature = %q, want %q", got, tc.want)
			}

			out := make([]byte, len(payload)+1024)
			dn, err := NewCompressor().Depack(buf[:n], 0, out, tc.method)
			if err != nil {
				t.Fatalf("Depack failed: %v", err)
			}
			if dn != len(payload) || !bytes.Equal(out[:dn], payload) {
				t.Errorf("payload mismatch after Depack: %d bytes", dn)
			}
		})
	}
}
