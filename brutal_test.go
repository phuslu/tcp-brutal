//go:build linux

package brutal

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"unsafe"
)

const (
	linkCreateAttrSize = unsafe.Sizeof(linkCreateAttr{})
	objInfoAttrSize    = unsafe.Sizeof(objInfoAttr{})
	linkInfoDataOffset = unsafe.Offsetof(bpfLinkInfo{}.Data)
	progInfoNameOffset = unsafe.Offsetof(bpfProgInfo{}.Name)
	mapInfoNameOffset  = unsafe.Offsetof(bpfMapInfo{}.Name)
)

var (
	_ [64 - linkCreateAttrSize]byte
	_ [linkCreateAttrSize - 64]byte
	_ [16 - objInfoAttrSize]byte
	_ [objInfoAttrSize - 16]byte
	_ [16 - linkInfoDataOffset]byte
	_ [linkInfoDataOffset - 16]byte
	_ [64 - progInfoNameOffset]byte
	_ [progInfoNameOffset - 64]byte
	_ [24 - mapInfoNameOffset]byte
	_ [mapInfoNameOffset - 24]byte
)

func TestBPFObjectName(t *testing.T) {
	tests := []struct {
		name      string
		bigEndian bool
		legacy    bool
		want      string
	}{
		{name: "little", want: "brutal_linux_bpfel.o"},
		{name: "big", bigEndian: true, want: "brutal_linux_bpfeb.o"},
		{name: "legacy little", legacy: true, want: "brutal_legacy_linux_bpfel.o"},
		{name: "legacy big", bigEndian: true, legacy: true, want: "brutal_legacy_linux_bpfeb.o"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bpfObjectName(tt.bigEndian, tt.legacy); got != tt.want {
				t.Fatalf("object name = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCoreRelocationsApplyAgainstLocalBTF(t *testing.T) {
	for _, name := range []string{
		"brutal_linux_bpfel.o",
		"brutal_linux_bpfeb.o",
		"brutal_legacy_linux_bpfel.o",
		"brutal_legacy_linux_bpfeb.o",
	} {
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

func TestCoreRelocationsApplyAgainstRunningKernelBTF(t *testing.T) {
	data, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		t.Skipf("kernel BTF is unavailable: %v", err)
	}
	target, err := parseBTF(data)
	if err != nil {
		t.Fatalf("parse kernel BTF: %v", err)
	}
	ops, err := target.structOpsInfo("tcp_congestion_ops")
	if err != nil {
		t.Skipf("kernel doesn't expose link-managed TCP struct_ops: %v", err)
	}
	params, err := target.tcpCongControlParamCount(ops)
	if err != nil {
		t.Fatal(err)
	}
	objectData, objectName, err := selectObject(params)
	if err != nil {
		t.Skipf("kernel TCP callback ABI isn't supported: %v", err)
	}
	obj, err := parseBPFObject(objectData, objectName)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range obj.programs {
		insns := append([]byte(nil), spec.instructions...)
		if err := spec.applyCoreRelocs(insns, obj.btfSpec, target, obj.order); err != nil {
			t.Fatalf("%s: %v", spec.name, err)
		}
	}
}

func TestCoreArrayFlavorAndFieldExists(t *testing.T) {
	local := &btfSpec{order: binary.LittleEndian, types: []*btfType{
		{id: 1, name: "int", kind: btfKindInt, size: 4},
		{id: 2, kind: btfKindArray, array: &btfArray{typeID: 1, indexTypeID: 1, nelems: 2}},
		{id: 3, name: "sample___local", kind: btfKindStruct, size: 8, members: []btfMember{
			{name: "values", typeID: 2},
		}},
	}}
	target := &btfSpec{order: binary.LittleEndian, types: []*btfType{
		{id: 1, name: "int", kind: btfKindInt, size: 4},
		{id: 2, kind: btfKindArray, array: &btfArray{typeID: 1, indexTypeID: 1, nelems: 4}},
		{id: 3, name: "sample", kind: btfKindStruct, size: 24, members: []btfMember{
			{name: "padding", typeID: 1},
			{name: "values", typeID: 2, bitOffset: 64},
		}},
	}}

	got, err := resolveCoreFieldReloc(local, target, 3, "0:0:1", bpfCoreFieldByteOffset, binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	if got != 12 {
		t.Fatalf("array field byte offset = %d, want 12", got)
	}
	got, err = resolveCoreFieldReloc(local, target, 3, "0:0", bpfCoreFieldExists, binary.LittleEndian)
	if err != nil || got != 1 {
		t.Fatalf("existing field relocation = %d, %v; want 1, nil", got, err)
	}
	target.types[2].members[1].name = "renamed"
	got, err = resolveCoreFieldReloc(local, target, 3, "0:0", bpfCoreFieldExists, binary.LittleEndian)
	if err != nil || got != 0 {
		t.Fatalf("missing field relocation = %d, %v; want 0, nil", got, err)
	}
}

func TestCoreBitfieldContainerWidening(t *testing.T) {
	spec := &btfSpec{types: []*btfType{{id: 1, name: "u8", kind: btfKindInt, size: 1}}}
	field := coreField{typeID: 1, bitOffset: 7, bitfieldSize: 2}
	if err := spec.adjustCoreBitfield(&field); err != nil {
		t.Fatal(err)
	}
	if field.loadSize != 2 || field.bitfieldOffset != 7 {
		t.Fatalf("bitfield layout = load %d, offset %d; want load 2, offset 7", field.loadSize, field.bitfieldOffset)
	}
	offset, err := spec.coreBitfieldByteOffset(field)
	if err != nil || offset != 0 {
		t.Fatalf("bitfield byte offset = %d, %v; want 0, nil", offset, err)
	}
}

func TestCoreTypeAndEnumRelocations(t *testing.T) {
	negativeOneSigned := int64(-1)
	negativeTwoSigned := int64(-2)
	negativeTwo := uint64(negativeTwoSigned)
	local := &btfSpec{types: []*btfType{
		{id: 1, name: "int", kind: btfKindInt, size: 4, intEncoding: btfIntSigned},
		{id: 2, name: "sample___local", kind: btfKindStruct, size: 4, members: []btfMember{{name: "value", typeID: 1}}},
		{id: 3, name: "mode___local", kind: btfKindEnum, size: 4, kindFlag: true, enumValues: []btfEnumValue{{name: "MODE_A___local", value: uint64(negativeOneSigned)}}},
	}}
	target := &btfSpec{types: []*btfType{
		{id: 1, name: "int", kind: btfKindInt, size: 4, intEncoding: btfIntSigned},
		{id: 2, name: "sample", kind: btfKindStruct, size: 8, members: []btfMember{{name: "value", typeID: 1}}},
		{id: 3, name: "mode", kind: btfKindEnum64, size: 8, kindFlag: true, enumValues: []btfEnumValue{{name: "MODE_A", value: negativeTwo}}},
	}}

	for _, tt := range []struct {
		kind uint32
		want uint64
	}{
		{bpfCoreTypeIDTarget, 2},
		{bpfCoreTypeExists, 1},
		{bpfCoreTypeSize, 8},
		{bpfCoreTypeMatches, 1},
	} {
		got, err := resolveCoreTypeReloc(local, target, 2, "0", tt.kind)
		if err != nil || got != tt.want {
			t.Fatalf("type relocation %d = %d, %v; want %d, nil", tt.kind, got, err, tt.want)
		}
	}
	got, err := resolveCoreEnumReloc(local, target, 3, "0", bpfCoreEnumvalExists)
	if err != nil || got != 1 {
		t.Fatalf("enum existence = %d, %v; want 1, nil", got, err)
	}
	got, err = resolveCoreEnumReloc(local, target, 3, "0", bpfCoreEnumvalValue)
	if err != nil || got != negativeTwo {
		t.Fatalf("enum value = %d, %v; want %d, nil", got, err, negativeTwo)
	}
}

func TestPatchCoreReloc64BitImmediate(t *testing.T) {
	insns := make([]byte, 16)
	insns[0] = 0x18
	value := uint64(0x1122334455667788)
	if err := patchCoreReloc(insns, 0, value, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(insns[4:8]); got != uint32(value) {
		t.Fatalf("low immediate = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(insns[12:16]); got != uint32(value>>32) {
		t.Fatalf("high immediate = %#x", got)
	}
}

func TestStructOpsValueUsesTargetLayout(t *testing.T) {
	name := bpfObjectName(nativeEndianIsBig(), false)
	data, err := bpfObjects.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := parseBPFObject(data, name)
	if err != nil {
		t.Fatal(err)
	}
	target := &btfSpec{types: []*btfType{
		{id: 1, name: "char", kind: btfKindInt, size: 1},
		{id: 2, kind: btfKindArray, array: &btfArray{typeID: 1, indexTypeID: 3, nelems: 16}},
		{id: 3, name: "unsigned int", kind: btfKindInt, size: 4},
		{id: 4, kind: btfKindPtr},
	}}
	ops := &structOpsInfo{
		valueSize:  160,
		dataOffset: 16,
		members: map[string]structOpsMember{
			"name":         {offset: 8, typeID: 2},
			"flags":        {offset: 32, typeID: 3},
			"init":         {offset: 48, typeID: 4},
			"cong_control": {offset: 56, typeID: 4},
			"undo_cwnd":    {offset: 64, typeID: 4},
			"ssthresh":     {offset: 72, typeID: 4},
			"release":      {offset: 80, typeID: 4},
		},
	}
	programs := map[string]int{
		"brutal_init":         101,
		"brutal_cong_control": 102,
		"brutal_undo_cwnd":    103,
		"brutal_ssthresh":     104,
		"brutal_release":      105,
	}
	value, err := obj.structOpsValue(ops, target, programs)
	if err != nil {
		t.Fatal(err)
	}
	sourceName, err := obj.structOpsSourceField("name")
	if err != nil {
		t.Fatal(err)
	}
	if got := value[24:40]; !bytes.Equal(got, sourceName) {
		t.Fatalf("target name = %q, want %q", got, sourceName)
	}
	if got := nativeByteOrder().Uint64(value[64:72]); got != 101 {
		t.Fatalf("target init fd = %d, want 101", got)
	}
}

func TestInstallationSummaryIsDeterministic(t *testing.T) {
	state := installationState{
		algorithm:  true,
		structOps:  pinnedLinkState{exists: true, valid: true},
		setsockopt: pinnedLinkState{exists: true, reason: "wrong cgroup"},
	}
	want := "algorithm is registered; struct_ops link is valid; setsockopt link is invalid: wrong cgroup"
	for i := 0; i < 100; i++ {
		if got := state.summary(); got != want {
			t.Fatalf("summary = %q, want %q", got, want)
		}
	}
}

func TestBPFABIStructLayouts(t *testing.T) {
	if got := unsafe.Sizeof(linkCreateAttr{}); got != 64 {
		t.Fatalf("linkCreateAttr size = %d, want 64", got)
	}
	if got := unsafe.Sizeof(objInfoAttr{}); got != 16 {
		t.Fatalf("objInfoAttr size = %d, want 16", got)
	}
	var linkInfo bpfLinkInfo
	if got := unsafe.Offsetof(linkInfo.Data); got != 16 {
		t.Fatalf("bpfLinkInfo data offset = %d, want 16", got)
	}
	var progInfo bpfProgInfo
	if got := unsafe.Offsetof(progInfo.Name); got != 64 {
		t.Fatalf("bpfProgInfo name offset = %d, want 64", got)
	}
	var mapInfo bpfMapInfo
	if got := unsafe.Offsetof(mapInfo.Name); got != 24 {
		t.Fatalf("bpfMapInfo name offset = %d, want 24", got)
	}
}

func TestEncodeUintRejectsOverflow(t *testing.T) {
	if err := encodeUint(make([]byte, 1), 256, binary.LittleEndian); err == nil || !strings.Contains(err.Error(), "does not fit") {
		t.Fatalf("encode overflow error = %v", err)
	}
}

func TestParseBPFObjectKind(t *testing.T) {
	for _, tt := range []struct {
		name string
		data string
		want bpfFDKind
	}{
		{name: "map", data: "pos:\t0\nmap_type:\t26\n", want: bpfFDMap},
		{name: "program", data: "prog_type:\t25\nprog_id:\t7\n", want: bpfFDProgram},
		{name: "link", data: "link_type:\tstruct_ops\nlink_id:\t8\n", want: bpfFDLink},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBPFObjectKind([]byte(tt.data))
			if err != nil || got != tt.want {
				t.Fatalf("kind = %v, %v; want %v, nil", got, err, tt.want)
			}
		})
	}
	if _, err := parseBPFObjectKind([]byte("pos:\t0\n")); err == nil {
		t.Fatal("missing BPF object kind was accepted")
	}
	if _, err := parseBPFObjectKind([]byte("map_type:\t1\nlink_type:\tcgroup\n")); err == nil {
		t.Fatal("conflicting BPF object kinds were accepted")
	}
}
