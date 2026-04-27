//go:build linux

package brutal

import "testing"

func TestBPFObjectName(t *testing.T) {
	if got := bpfObjectName(false); got != "brutal_linux_bpfel.o" {
		t.Fatalf("little-endian object = %q", got)
	}
	if got := bpfObjectName(true); got != "brutal_linux_bpfeb.o" {
		t.Fatalf("big-endian object = %q", got)
	}
}

func TestCoreRelocationsApplyAgainstLocalBTF(t *testing.T) {
	for _, name := range []string{"brutal_linux_bpfel.o", "brutal_linux_bpfeb.o"} {
		t.Run(name, func(t *testing.T) {
			data, err := bpfObjects.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}

			obj, err := parseBPFObject(data, name)
			if err != nil {
				t.Fatal(err)
			}

			var count int
			for _, spec := range obj.programs {
				count += len(spec.coreRelocs)

				insns := make([]byte, len(spec.instructions))
				copy(insns, spec.instructions)
				for _, rel := range spec.relocs {
					if rel.Symbol != "brutal_sk_storage" {
						continue
					}
					if err := patchMapReloc(insns, rel.Offset, 42, obj.order); err != nil {
						t.Fatalf("%s: map reloc: %v", spec.name, err)
					}
					insn := insns[rel.Offset : rel.Offset+16]
					if byteOrderIsBig(obj.order) {
						if got := insn[1] & 0x0f; got != bpfPseudoMapFD {
							t.Fatalf("%s: big-endian map src_reg = %d", spec.name, got)
						}
					} else if got := insn[1] >> 4; got != bpfPseudoMapFD {
						t.Fatalf("%s: little-endian map src_reg = %d", spec.name, got)
					}
					if got := obj.order.Uint32(insn[4:8]); got != 42 {
						t.Fatalf("%s: map fd immediate = %d", spec.name, got)
					}
				}
				if err := spec.applyCoreRelocs(insns, obj.btfSpec, obj.btfSpec, obj.order); err != nil {
					t.Fatalf("%s: %v", spec.name, err)
				}
			}
			if count == 0 {
				t.Fatal("expected CO-RE relocations")
			}
		})
	}
}
