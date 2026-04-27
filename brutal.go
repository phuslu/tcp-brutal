//go:build linux

package brutal

import (
	"bytes"
	"debug/elf"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	defaultCgroupPath = "/sys/fs/cgroup"
	defaultPinRoot    = "/sys/fs/bpf"

	tcpAvailableCongestionControl = "/proc/sys/net/ipv4/tcp_available_congestion_control"

	bpfObjectLittleEndianName = "brutal_linux_bpfel.o"
	bpfObjectBigEndianName    = "brutal_linux_bpfeb.o"
	structOpsPinPath          = defaultPinRoot + "/brutal_cc"
	setsockoptPinPath         = defaultPinRoot + "/brutal_setsockopt"
)

const (
	bpfMapCreate    = 0
	bpfMapUpdate    = 2
	bpfMapDelete    = 3
	bpfProgLoad     = 5
	bpfObjPin       = 6
	bpfObjGet       = 7
	bpfProgAttach   = 8
	bpfProgDetach   = 9
	bpfBTFLoad      = 18
	bpfMapTypeSk    = 24
	bpfMapTypeOps   = 26
	bpfProgCgrpOpt  = 25
	bpfProgOps      = 27
	bpfAttachSetOpt = 22
	bpfFSMagic      = uint32(0xcafe4a11)
	bpfFNoPrealloc  = 1
	bpfFAllowMulti  = 2
	bpfPseudoMapFD  = 1
	rlimitMemlock   = 8
)

const (
	bpfClassLD    = 0x00
	bpfClassLDX   = 0x01
	bpfClassST    = 0x02
	bpfClassSTX   = 0x03
	bpfClassALU   = 0x04
	bpfClassALU64 = 0x07
	bpfClassMask  = 0x07
	bpfSrcX       = 0x08

	bpfCoreFieldByteOffset = 0
	btfMagic               = 0xeb9f
)

const (
	btfKindInt       = 1
	btfKindPtr       = 2
	btfKindArray     = 3
	btfKindStruct    = 4
	btfKindUnion     = 5
	btfKindEnum      = 6
	btfKindFwd       = 7
	btfKindTypedef   = 8
	btfKindVolatile  = 9
	btfKindConst     = 10
	btfKindRestrict  = 11
	btfKindFunc      = 12
	btfKindFuncProto = 13
	btfKindVar       = 14
	btfKindDatasec   = 15
	btfKindFloat     = 16
	btfKindDeclTag   = 17
	btfKindTypeTag   = 18
	btfKindEnum64    = 19
)

//go:embed brutal_*.o
var bpfObjects embed.FS

type Options struct {
	CgroupPath string
	Force      bool
}

type loadedBPF struct {
	fds []int
}

type bpfObject struct {
	name           string
	order          binary.ByteOrder
	license        string
	btf            []byte
	btfSpec        *btfSpec
	mapKeyTypeID   uint32
	mapValueTypeID uint32
	mapValueSize   uint32
	programs       map[string]*programSpec
	structOpsData  []byte
}

type programSpec struct {
	name               string
	progType           uint32
	expectedAttachType uint32
	attachBTFID        uint32
	memberName         string
	instructions       []byte
	relocs             []elfReloc
	coreRelocs         []coreReloc
}

var brutalPrograms = [...]struct {
	name       string
	memberName string
}{
	{name: "brutal_setsockopt", memberName: ""},
	{name: "brutal_init", memberName: "init"},
	{name: "brutal_cong_control", memberName: "cong_control"},
	{name: "brutal_undo_cwnd", memberName: "undo_cwnd"},
	{name: "brutal_ssthresh", memberName: "ssthresh"},
	{name: "brutal_release", memberName: "release"},
}

type elfSymbol struct {
	Name    string
	Section elf.SectionIndex
	Value   uint64
	Size    uint64
}

type elfReloc struct {
	Offset uint64
	Symbol string
}

type coreReloc struct {
	insnOffset uint32
	typeID     uint32
	access     string
	kind       uint32
}

type structOpsInfo struct {
	valueTypeID uint32
	valueSize   uint32
	dataOffset  uint32
	innerTypeID uint32
	members     map[string]structOpsMember
}

type structOpsMember struct {
	index  uint32
	offset uint32
	typeID uint32
}

type mapCreateAttr struct {
	MapType               uint32
	KeySize               uint32
	ValueSize             uint32
	MaxEntries            uint32
	MapFlags              uint32
	InnerMapFd            uint32
	NumaNode              uint32
	MapName               [16]byte
	MapIfindex            uint32
	BtfFd                 uint32
	BtfKeyTypeID          uint32
	BtfValueTypeID        uint32
	BtfVmlinuxValueTypeID uint32
	MapExtra              uint64
	ValueTypeBTFObjFd     int32
	MapTokenFd            int32
	ExclProgHash          uint64
	ExclProgHashSize      uint32
	_                     [4]byte
}

type progLoadAttr struct {
	ProgType           uint32
	InsnCnt            uint32
	Insns              uint64
	License            uint64
	LogLevel           uint32
	LogSize            uint32
	LogBuf             uint64
	KernVersion        uint32
	ProgFlags          uint32
	ProgName           [16]byte
	ProgIfindex        uint32
	ExpectedAttachType uint32
	ProgBtfFd          uint32
	FuncInfoRecSize    uint32
	FuncInfo           uint64
	FuncInfoCnt        uint32
	LineInfoRecSize    uint32
	LineInfo           uint64
	LineInfoCnt        uint32
	AttachBtfID        uint32
	AttachBtfObjFd     uint32
	CoreReloCnt        uint32
	FdArray            uint64
	CoreRelos          uint64
	CoreReloRecSize    uint32
	LogTrueSize        uint32
	ProgTokenFd        int32
	FdArrayCnt         uint32
	Signature          uint64
	SignatureSize      uint32
	KeyringID          int32
}

type btfLoadAttr struct {
	Btf            uint64
	BtfLogBuf      uint64
	BtfSize        uint32
	BtfLogSize     uint32
	BtfLogLevel    uint32
	BtfLogTrueSize uint32
	BtfFlags       uint32
	BtfTokenFd     int32
}

type mapElemAttr struct {
	MapFd uint32
	_     uint32
	Key   uint64
	Value uint64
	Flags uint64
}

type objPinAttr struct {
	Pathname  uint64
	BpfFd     uint32
	FileFlags uint32
	PathFd    int32
	_         [4]byte
}

type progAttachAttr struct {
	TargetFd         uint32
	AttachBpfFd      uint32
	AttachType       uint32
	AttachFlags      uint32
	ReplaceBpfFd     uint32
	RelativeFdOrID   uint32
	ExpectedRevision uint64
}

type progDetachAttr struct {
	TargetFd         uint32
	AttachBpfFd      uint32
	AttachType       uint32
	AttachFlags      uint32
	_                uint32
	RelativeFdOrID   uint32
	ExpectedRevision uint64
}

func Load() error {
	return LoadWithOptions(Options{})
}

func (opts Options) Load() error {
	return LoadWithOptions(opts)
}

func LoadWithOptions(opts Options) error {
	opts = opts.withDefaults()

	if IsLoaded() {
		return nil
	}

	if err := removeMemlockLimit(); err != nil {
		return fmt.Errorf("raise memlock rlimit: %w", err)
	}

	if opts.Force {
		if err := unload(opts); err != nil {
			return err
		}
	}

	if err := ensurePinRoot(); err != nil {
		return err
	}

	loadedBPF, err := loadBPF(opts)
	if err != nil {
		return err
	}
	loadedBPF.close()
	return nil
}

func Unload() error {
	return UnloadWithOptions(Options{})
}

func (opts Options) Unload() error {
	return UnloadWithOptions(opts)
}

func UnloadWithOptions(opts Options) error {
	return unload(opts.withDefaults())
}

func IsLoaded() bool {
	data, err := os.ReadFile(tcpAvailableCongestionControl)
	if err != nil {
		return false
	}
	for _, algo := range strings.Fields(string(data)) {
		if algo == "brutal" {
			return true
		}
	}
	return false
}

func (opts Options) withDefaults() Options {
	if opts.CgroupPath == "" {
		opts.CgroupPath = defaultCgroupPath
	}
	return opts
}

func loadBPF(opts Options) (_ *loadedBPF, err error) {
	objBytes, objName, err := selectObject()
	if err != nil {
		return nil, err
	}

	obj, err := parseBPFObject(objBytes, objName)
	if err != nil {
		return nil, err
	}

	kernelBTF, err := loadKernelBTF()
	if err != nil {
		return nil, err
	}

	opsInfo, err := kernelBTF.structOpsInfo("tcp_congestion_ops")
	if err != nil {
		return nil, err
	}
	if err := kernelBTF.requireTCP610(opsInfo); err != nil {
		return nil, err
	}

	objBTF, err := btfLoad(obj.btf)
	if err != nil {
		return nil, fmt.Errorf("load BTF from %s: %w", obj.name, err)
	}
	defer syscall.Close(objBTF)

	skStorage, err := createSkStorageMap(objBTF, obj)
	if err != nil {
		return nil, err
	}
	loaded := &loadedBPF{fds: []int{skStorage}}
	defer func() {
		if err != nil {
			loaded.close()
		}
	}()

	programs, err := loadPrograms(obj, skStorage, objBTF, opsInfo, kernelBTF)
	if err != nil {
		return nil, err
	}
	for _, fd := range programs {
		loaded.fds = append(loaded.fds, fd)
	}

	structMap, err := createStructOpsMap(objBTF, opsInfo)
	if err != nil {
		return nil, err
	}
	loaded.fds = append(loaded.fds, structMap)
	defer func() {
		if err != nil {
			_ = unregisterStructOps(structMap)
			_ = unlinkIfExists(structOpsPinPath)
		}
	}()

	value, err := obj.structOpsValue(opsInfo, programs)
	if err != nil {
		return nil, err
	}
	if err = mapUpdate(structMap, 0, value); err != nil {
		return nil, fmt.Errorf("register struct_ops brutal: %w", err)
	}

	if err = objPin(structMap, structOpsPinPath); err != nil {
		return nil, fmt.Errorf("pin struct_ops map %s: %w", structOpsPinPath, err)
	}

	if err = attachSetsockopt(programs["brutal_setsockopt"], opts.CgroupPath, setsockoptPinPath); err != nil {
		return nil, err
	}

	return loaded, nil
}

func (l *loadedBPF) close() {
	if l == nil {
		return
	}
	for i := len(l.fds) - 1; i >= 0; i-- {
		_ = syscall.Close(l.fds[i])
	}
	l.fds = nil
}

func selectObject() ([]byte, string, error) {
	name := bpfObjectName(nativeEndianIsBig())
	data, err := bpfObjects.ReadFile(name)
	if err == nil {
		return data, name, nil
	}

	available, _ := fs.Glob(bpfObjects, "brutal_*.o")
	if len(available) == 0 {
		return nil, "", fmt.Errorf("embedded BPF object %s not found; build the BPF object first", name)
	}
	return nil, "", fmt.Errorf("embedded BPF object %s not found; available objects: %s", name, strings.Join(available, ", "))
}

func bpfObjectName(bigEndian bool) string {
	if bigEndian {
		return bpfObjectBigEndianName
	}
	return bpfObjectLittleEndianName
}

func parseBPFObject(data []byte, name string) (*bpfObject, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse embedded BPF object %s: %w", name, err)
	}

	symbols, err := readELFSymbols(f)
	if err != nil {
		return nil, fmt.Errorf("read symbols from %s: %w", name, err)
	}

	relocs, err := readELFRelocs(f, symbols)
	if err != nil {
		return nil, fmt.Errorf("read relocations from %s: %w", name, err)
	}

	btfRaw, err := sectionData(f, ".BTF")
	if err != nil {
		return nil, err
	}
	btfRaw, err = sanitizeObjectBTF(btfRaw, f)
	if err != nil {
		return nil, fmt.Errorf("sanitize BTF from %s: %w", name, err)
	}
	objBTF, err := parseBTF(btfRaw)
	if err != nil {
		return nil, fmt.Errorf("parse BTF from %s: %w", name, err)
	}

	licenseData, err := sectionData(f, "license")
	if err != nil {
		return nil, err
	}
	license := strings.TrimRight(string(licenseData), "\x00")
	if license == "" {
		return nil, fmt.Errorf("empty license in %s", name)
	}

	keyTypeID, valueTypeID, valueSize, err := objBTF.mapTypeIDs("brutal_sk_storage")
	if err != nil {
		return nil, err
	}

	structOpsData, err := structOpsData(f, objBTF, symbols)
	if err != nil {
		return nil, err
	}

	coreRelocs, err := parseBTFExtCoreRelocs(f, objBTF)
	if err != nil {
		return nil, fmt.Errorf("parse CO-RE relocations from %s: %w", name, err)
	}

	programs, err := programSpecs(f, symbols, relocs, coreRelocs)
	if err != nil {
		return nil, err
	}

	return &bpfObject{
		name:           name,
		order:          f.ByteOrder,
		license:        license,
		btf:            btfRaw,
		btfSpec:        objBTF,
		mapKeyTypeID:   keyTypeID,
		mapValueTypeID: valueTypeID,
		mapValueSize:   valueSize,
		programs:       programs,
		structOpsData:  structOpsData,
	}, nil
}

func sectionData(f *elf.File, name string) ([]byte, error) {
	sec := f.Section(name)
	if sec == nil {
		return nil, fmt.Errorf("BPF object is missing section %s", name)
	}
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("read section %s: %w", name, err)
	}
	return data, nil
}

func readELFSymbols(f *elf.File) ([]elfSymbol, error) {
	symtab := f.Section(".symtab")
	if symtab == nil {
		return nil, errors.New("BPF object is missing .symtab")
	}
	if int(symtab.Link) >= len(f.Sections) {
		return nil, errors.New(".symtab has invalid string table link")
	}
	strtab, err := f.Sections[symtab.Link].Data()
	if err != nil {
		return nil, fmt.Errorf("read .symtab strings: %w", err)
	}
	data, err := symtab.Data()
	if err != nil {
		return nil, fmt.Errorf("read .symtab: %w", err)
	}
	if symtab.Entsize == 0 {
		return nil, errors.New(".symtab has zero entry size")
	}

	symbols := make([]elfSymbol, 0, len(data)/int(symtab.Entsize))
	for off := uint64(0); off+symtab.Entsize <= uint64(len(data)); off += symtab.Entsize {
		entry := data[off : off+symtab.Entsize]
		nameOff := f.ByteOrder.Uint32(entry[0:4])
		name := stringFromTable(strtab, nameOff)
		symbols = append(symbols, elfSymbol{
			Name:    name,
			Section: elf.SectionIndex(f.ByteOrder.Uint16(entry[6:8])),
			Value:   f.ByteOrder.Uint64(entry[8:16]),
			Size:    f.ByteOrder.Uint64(entry[16:24]),
		})
	}
	return symbols, nil
}

func readELFRelocs(f *elf.File, symbols []elfSymbol) (map[elf.SectionIndex][]elfReloc, error) {
	relocs := make(map[elf.SectionIndex][]elfReloc)
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_REL {
			continue
		}
		if sec.Entsize == 0 {
			return nil, fmt.Errorf("relocation section %s has zero entry size", sec.Name)
		}
		data, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("read relocation section %s: %w", sec.Name, err)
		}
		target := elf.SectionIndex(sec.Info)
		for off := uint64(0); off+sec.Entsize <= uint64(len(data)); off += sec.Entsize {
			entry := data[off : off+sec.Entsize]
			rOff := f.ByteOrder.Uint64(entry[0:8])
			info := f.ByteOrder.Uint64(entry[8:16])
			symIdx := info >> 32
			if symIdx >= uint64(len(symbols)) {
				return nil, fmt.Errorf("relocation %s references invalid symbol %d", sec.Name, symIdx)
			}
			relocs[target] = append(relocs[target], elfReloc{
				Offset: rOff,
				Symbol: symbols[symIdx].Name,
			})
		}
	}
	return relocs, nil
}

func parseBTFExtCoreRelocs(f *elf.File, btf *btfSpec) (map[elf.SectionIndex][]coreReloc, error) {
	sec := f.Section(".BTF.ext")
	if sec == nil {
		return nil, nil
	}
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("read section .BTF.ext: %w", err)
	}
	if len(data) < 32 {
		return nil, errors.New(".BTF.ext data is too short")
	}
	order := btf.order
	if order.Uint16(data[0:2]) != btfMagic {
		return nil, fmt.Errorf("invalid .BTF.ext magic %#x", order.Uint16(data[0:2]))
	}
	if data[2] != 1 {
		return nil, fmt.Errorf("unsupported .BTF.ext version %d", data[2])
	}

	hdrLen := order.Uint32(data[4:8])
	coreOff := order.Uint32(data[24:28])
	coreLen := order.Uint32(data[28:32])
	if hdrLen < 32 || hdrLen > uint32(len(data)) {
		return nil, errors.New(".BTF.ext header length is invalid")
	}
	if coreLen == 0 {
		return nil, nil
	}
	coreStart := hdrLen + coreOff
	coreEnd := coreStart + coreLen
	if coreStart < hdrLen || coreEnd < coreStart || coreEnd > uint32(len(data)) {
		return nil, errors.New(".BTF.ext CO-RE relocation section is outside data")
	}

	coreData := data[coreStart:coreEnd]
	if len(coreData) < 4 {
		return nil, errors.New(".BTF.ext CO-RE relocation section is too short")
	}
	recSize := order.Uint32(coreData[0:4])
	if recSize < 16 {
		return nil, fmt.Errorf("unsupported CO-RE relocation record size %d", recSize)
	}

	result := make(map[elf.SectionIndex][]coreReloc)
	for off := uint32(4); off < uint32(len(coreData)); {
		if off+8 > uint32(len(coreData)) {
			return nil, errors.New("truncated CO-RE relocation section header")
		}
		secNameOff := order.Uint32(coreData[off : off+4])
		numInfo := order.Uint32(coreData[off+4 : off+8])
		off += 8

		sectionName := btf.string(secNameOff)
		sectionIndex, ok := sectionIndexByName(f, sectionName)
		if !ok {
			return nil, fmt.Errorf("CO-RE relocation references missing section %q", sectionName)
		}

		for i := uint32(0); i < numInfo; i++ {
			if off+recSize > uint32(len(coreData)) {
				return nil, errors.New("truncated CO-RE relocation record")
			}
			rec := coreData[off : off+recSize]
			accessOff := order.Uint32(rec[8:12])
			result[sectionIndex] = append(result[sectionIndex], coreReloc{
				insnOffset: order.Uint32(rec[0:4]),
				typeID:     order.Uint32(rec[4:8]),
				access:     btf.string(accessOff),
				kind:       order.Uint32(rec[12:16]),
			})
			off += recSize
		}
	}
	return result, nil
}

func sectionIndexByName(f *elf.File, name string) (elf.SectionIndex, bool) {
	for i, sec := range f.Sections {
		if sec.Name == name {
			return elf.SectionIndex(i), true
		}
	}
	return 0, false
}

func structOpsData(f *elf.File, btf *btfSpec, symbols []elfSymbol) ([]byte, error) {
	if _, err := btf.varTypeID("brutal"); err != nil {
		return nil, err
	}

	sym := findSymbol(symbols, "brutal")
	if sym == nil {
		return nil, errors.New("BPF object is missing symbol brutal")
	}
	if int(sym.Section) >= len(f.Sections) {
		return nil, errors.New("symbol brutal has invalid section")
	}
	data, err := f.Sections[sym.Section].Data()
	if err != nil {
		return nil, fmt.Errorf("read struct_ops section %s: %w", f.Sections[sym.Section].Name, err)
	}
	if sym.Value+sym.Size > uint64(len(data)) {
		return nil, errors.New("symbol brutal is outside its section")
	}

	buf := make([]byte, sym.Size)
	copy(buf, data[sym.Value:sym.Value+sym.Size])
	return buf, nil
}

func programSpecs(f *elf.File, symbols []elfSymbol, relocs map[elf.SectionIndex][]elfReloc, coreRelocs map[elf.SectionIndex][]coreReloc) (map[string]*programSpec, error) {
	result := make(map[string]*programSpec)

	for _, def := range brutalPrograms {
		name := def.name
		sym := findSymbol(symbols, name)
		if sym == nil {
			return nil, fmt.Errorf("BPF object is missing program symbol %s", name)
		}
		if int(sym.Section) >= len(f.Sections) {
			return nil, fmt.Errorf("program symbol %s has invalid section", name)
		}
		sec := f.Sections[sym.Section]
		data, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("read program section %s: %w", sec.Name, err)
		}
		if sym.Value+sym.Size > uint64(len(data)) {
			return nil, fmt.Errorf("program symbol %s is outside section %s", name, sec.Name)
		}

		insns := make([]byte, sym.Size)
		copy(insns, data[sym.Value:sym.Value+sym.Size])
		spec := &programSpec{name: name, memberName: def.memberName, instructions: insns}
		if def.memberName == "" {
			spec.progType = bpfProgCgrpOpt
			spec.expectedAttachType = bpfAttachSetOpt
		} else {
			spec.progType = bpfProgOps
		}

		for _, rel := range relocs[sym.Section] {
			if rel.Offset >= sym.Value && rel.Offset < sym.Value+sym.Size {
				rel.Offset -= sym.Value
				spec.relocs = append(spec.relocs, rel)
			}
		}
		for _, rel := range coreRelocs[sym.Section] {
			offset := uint64(rel.insnOffset)
			if offset >= sym.Value && offset < sym.Value+sym.Size {
				rel.insnOffset = uint32(offset - sym.Value)
				spec.coreRelocs = append(spec.coreRelocs, rel)
			}
		}
		result[name] = spec
	}

	return result, nil
}

func findSymbol(symbols []elfSymbol, name string) *elfSymbol {
	for i := range symbols {
		if symbols[i].Name == name {
			return &symbols[i]
		}
	}
	return nil
}

func loadKernelBTF() (*btfSpec, error) {
	data, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		return nil, fmt.Errorf("read /sys/kernel/btf/vmlinux: %w", err)
	}
	btf, err := parseBTF(data)
	if err != nil {
		return nil, fmt.Errorf("parse /sys/kernel/btf/vmlinux: %w", err)
	}
	return btf, nil
}

func loadPrograms(obj *bpfObject, skStorage, objBTF int, ops *structOpsInfo, kernelBTF *btfSpec) (map[string]int, error) {
	result := make(map[string]int)
	for _, def := range brutalPrograms {
		name := def.name
		spec := obj.programs[name]
		if spec == nil {
			return nil, fmt.Errorf("BPF object is missing program %s", name)
		}
		if spec.progType == bpfProgOps {
			member, ok := ops.members[spec.memberName]
			if !ok {
				return nil, fmt.Errorf("kernel tcp_congestion_ops is missing member %s", spec.memberName)
			}
			spec.attachBTFID = ops.innerTypeID
			spec.expectedAttachType = member.index
		}

		fd, err := spec.load(obj, kernelBTF, skStorage, objBTF)
		if err != nil {
			for _, loaded := range result {
				_ = syscall.Close(loaded)
			}
			return nil, err
		}
		result[name] = fd
	}
	return result, nil
}

func (p *programSpec) load(obj *bpfObject, kernelBTF *btfSpec, skStorage, objBTF int) (int, error) {
	insns := make([]byte, len(p.instructions))
	copy(insns, p.instructions)
	for _, rel := range p.relocs {
		if rel.Symbol != "brutal_sk_storage" {
			continue
		}
		if err := patchMapReloc(insns, rel.Offset, skStorage, obj.order); err != nil {
			return -1, fmt.Errorf("patch map relocation in %s: %w", p.name, err)
		}
	}
	if err := p.applyCoreRelocs(insns, obj.btfSpec, kernelBTF, obj.order); err != nil {
		return -1, fmt.Errorf("apply CO-RE relocations in %s: %w", p.name, err)
	}

	fd, err := progLoad(p, obj.license, insns, objBTF)
	if err != nil {
		return -1, fmt.Errorf("load program %s: %w", p.name, err)
	}
	return fd, nil
}

func patchMapReloc(insns []byte, offset uint64, mapFD int, order binary.ByteOrder) error {
	if offset+16 > uint64(len(insns)) {
		return fmt.Errorf("relocation offset %#x outside instruction stream", offset)
	}
	insn := insns[offset : offset+16]
	if byteOrderIsBig(order) {
		insn[1] = (insn[1] & 0xf0) | bpfPseudoMapFD
	} else {
		insn[1] = (insn[1] & 0x0f) | (bpfPseudoMapFD << 4)
	}
	order.PutUint32(insn[4:8], uint32(mapFD))
	order.PutUint32(insn[12:16], 0)
	return nil
}

func (p *programSpec) applyCoreRelocs(insns []byte, localBTF, targetBTF *btfSpec, order binary.ByteOrder) error {
	if len(p.coreRelocs) == 0 {
		return nil
	}
	if localBTF == nil || targetBTF == nil {
		return errors.New("missing local or target BTF")
	}
	for _, rel := range p.coreRelocs {
		if rel.kind != bpfCoreFieldByteOffset {
			return fmt.Errorf("unsupported CO-RE relocation kind %d at instruction offset %#x", rel.kind, rel.insnOffset)
		}
		value, err := resolveCoreFieldByteOffset(localBTF, targetBTF, rel.typeID, rel.access)
		if err != nil {
			return fmt.Errorf("resolve %q at instruction offset %#x: %w", rel.access, rel.insnOffset, err)
		}
		if err := patchCoreFieldByteOffset(insns, rel.insnOffset, value, order); err != nil {
			return err
		}
	}
	return nil
}

func resolveCoreFieldByteOffset(localBTF, targetBTF *btfSpec, typeID uint32, access string) (uint32, error) {
	accessors, err := parseCoreAccess(access)
	if err != nil {
		return 0, err
	}
	if len(accessors) == 0 || accessors[0] != 0 {
		return 0, fmt.Errorf("unsupported access path %q", access)
	}

	localType := localBTF.resolveType(typeID)
	if localType == nil {
		return 0, fmt.Errorf("local BTF type id %d not found", typeID)
	}
	targetType := targetBTF.find(localType.kind, localType.name)
	if targetType == nil {
		return 0, fmt.Errorf("target BTF is missing %s %q", btfKindName(localType.kind), localType.name)
	}

	var bitOffset uint32
	for _, index := range accessors[1:] {
		localType = localBTF.resolveType(localType.id)
		targetType = targetBTF.resolveType(targetType.id)
		if localType == nil || targetType == nil {
			return 0, errors.New("invalid BTF type while resolving access path")
		}
		if localType.kind != btfKindStruct && localType.kind != btfKindUnion {
			return 0, fmt.Errorf("local type %q is not a struct or union", localType.name)
		}
		if targetType.kind != btfKindStruct && targetType.kind != btfKindUnion {
			return 0, fmt.Errorf("target type %q is not a struct or union", targetType.name)
		}
		if index >= uint32(len(localType.members)) {
			return 0, fmt.Errorf("member index %d is outside local type %q", index, localType.name)
		}

		localMember := localType.members[index]
		targetMember := targetType.matchCoreMember(localMember.name, index)
		if targetMember == nil {
			return 0, fmt.Errorf("target type %q is missing member %q", targetType.name, localMember.name)
		}
		bitOffset += targetMember.bitOffset
		localType = localBTF.resolveType(localMember.typeID)
		targetType = targetBTF.resolveType(targetMember.typeID)
	}
	if bitOffset%8 != 0 {
		return 0, fmt.Errorf("resolved bit offset %d is not byte aligned", bitOffset)
	}
	return bitOffset / 8, nil
}

func parseCoreAccess(access string) ([]uint32, error) {
	if access == "" {
		return nil, errors.New("empty CO-RE access path")
	}
	parts := strings.Split(access, ":")
	accessors := make([]uint32, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid CO-RE access path %q: %w", access, err)
		}
		accessors = append(accessors, uint32(value))
	}
	return accessors, nil
}

func patchCoreFieldByteOffset(insns []byte, offset uint32, value uint32, order binary.ByteOrder) error {
	if offset%8 != 0 {
		return fmt.Errorf("CO-RE relocation offset %#x is not instruction aligned", offset)
	}
	if uint64(offset)+8 > uint64(len(insns)) {
		return fmt.Errorf("CO-RE relocation offset %#x outside instruction stream", offset)
	}

	insn := insns[offset : offset+8]
	switch insn[0] & bpfClassMask {
	case bpfClassLDX, bpfClassST, bpfClassSTX:
		if value > 32767 {
			return fmt.Errorf("CO-RE field byte offset %d does not fit BPF instruction offset", value)
		}
		order.PutUint16(insn[2:4], uint16(value))
	case bpfClassALU, bpfClassALU64:
		if insn[0]&bpfSrcX != 0 {
			return fmt.Errorf("CO-RE relocation at offset %#x targets register-source ALU instruction", offset)
		}
		order.PutUint32(insn[4:8], value)
	case bpfClassLD:
		return fmt.Errorf("CO-RE relocation at offset %#x targets unsupported load instruction", offset)
	default:
		return fmt.Errorf("CO-RE relocation at offset %#x targets unsupported instruction class %#x", offset, insn[0]&bpfClassMask)
	}
	return nil
}

func createSkStorageMap(objBTF int, obj *bpfObject) (int, error) {
	attr := mapCreateAttr{
		MapType:        bpfMapTypeSk,
		KeySize:        4,
		ValueSize:      obj.mapValueSize,
		MapFlags:       bpfFNoPrealloc,
		BtfFd:          uint32(objBTF),
		BtfKeyTypeID:   obj.mapKeyTypeID,
		BtfValueTypeID: obj.mapValueTypeID,
	}
	setObjName(&attr.MapName, "brutal_sk_storage")

	fd, err := bpf(bpfMapCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return -1, fmt.Errorf("create sk_storage map brutal_sk_storage: %w", err)
	}
	return fd, nil
}

func createStructOpsMap(objBTF int, ops *structOpsInfo) (int, error) {
	attr := mapCreateAttr{
		MapType:               bpfMapTypeOps,
		KeySize:               4,
		ValueSize:             ops.valueSize,
		MaxEntries:            1,
		BtfFd:                 uint32(objBTF),
		BtfVmlinuxValueTypeID: ops.valueTypeID,
	}
	setObjName(&attr.MapName, "brutal")

	fd, err := bpf(bpfMapCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return -1, fmt.Errorf("create struct_ops map brutal: %w", err)
	}
	return fd, nil
}

func (obj *bpfObject) structOpsValue(ops *structOpsInfo, programs map[string]int) ([]byte, error) {
	value := make([]byte, ops.valueSize)
	if ops.dataOffset > uint32(len(value)) {
		return nil, errors.New("struct_ops data offset exceeds value size")
	}
	copy(value[ops.dataOffset:], obj.structOpsData)
	order := nativeByteOrder()

	for _, def := range brutalPrograms {
		if def.memberName == "" {
			continue
		}
		progName, memberName := def.name, def.memberName
		fd, ok := programs[progName]
		if !ok {
			return nil, fmt.Errorf("program %s was not loaded", progName)
		}
		member, ok := ops.members[memberName]
		if !ok {
			return nil, fmt.Errorf("kernel tcp_congestion_ops is missing member %s", memberName)
		}
		offset := ops.dataOffset + member.offset
		if offset+8 > uint32(len(value)) {
			return nil, fmt.Errorf("member %s is outside struct_ops value", memberName)
		}
		order.PutUint64(value[offset:offset+8], uint64(fd))
	}
	return value, nil
}

func attachSetsockopt(progFD int, cgroupPath, pinPath string) error {
	cgroupFD, err := syscall.Open(cgroupPath, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open cgroup %s: %w", cgroupPath, err)
	}
	defer syscall.Close(cgroupFD)

	if err := progAttach(cgroupFD, progFD, bpfAttachSetOpt, bpfFAllowMulti); err != nil {
		return fmt.Errorf("attach cgroup setsockopt hook: %w", err)
	}

	if err := objPin(progFD, pinPath); err != nil {
		_ = progDetach(cgroupFD, progFD, bpfAttachSetOpt)
		return fmt.Errorf("pin cgroup setsockopt program %s: %w", pinPath, err)
	}

	return nil
}

func unload(opts Options) error {
	err := unloadSetsockopt(opts)

	if fd, getErr := objGet(structOpsPinPath); getErr == nil {
		if unregErr := unregisterStructOps(fd); unregErr != nil && err == nil {
			err = fmt.Errorf("unregister struct_ops map %s: %w", structOpsPinPath, unregErr)
		}
		_ = syscall.Close(fd)
	} else if !errors.Is(getErr, syscall.ENOENT) && err == nil {
		err = fmt.Errorf("open pinned struct_ops map %s: %w", structOpsPinPath, getErr)
	}
	if unlinkErr := unlinkIfExists(structOpsPinPath); unlinkErr != nil && err == nil {
		err = unlinkErr
	}

	return err
}

func ensurePinRoot() error {
	if err := os.Mkdir(defaultPinRoot, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create pin directory %s: %w", defaultPinRoot, err)
	}

	info, err := os.Stat(defaultPinRoot)
	if err != nil {
		return fmt.Errorf("stat pin directory %s: %w", defaultPinRoot, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("pin path %s is not a directory", defaultPinRoot)
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(defaultPinRoot, &stat); err != nil {
		return fmt.Errorf("statfs pin directory %s: %w", defaultPinRoot, err)
	}
	if uint32(stat.Type) != bpfFSMagic {
		return fmt.Errorf("pin directory %s is not bpffs", defaultPinRoot)
	}
	return nil
}

func unloadSetsockopt(opts Options) error {
	progFD, err := objGet(setsockoptPinPath)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open pinned cgroup setsockopt program %s: %w", setsockoptPinPath, err)
	}
	defer syscall.Close(progFD)

	cgroupFD, err := syscall.Open(opts.CgroupPath, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open cgroup %s: %w", opts.CgroupPath, err)
	}
	defer syscall.Close(cgroupFD)

	if err := progDetach(cgroupFD, progFD, bpfAttachSetOpt); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("detach cgroup setsockopt hook: %w", err)
	}

	return unlinkIfExists(setsockoptPinPath)
}

func removeMemlockLimit() error {
	limit := syscall.Rlimit{Cur: ^uint64(0), Max: ^uint64(0)}
	return syscall.Setrlimit(rlimitMemlock, &limit)
}

func btfLoad(data []byte) (int, error) {
	log := make([]byte, 1<<20)
	attr := btfLoadAttr{
		Btf:         bytePtr(data),
		BtfLogBuf:   bytePtr(log),
		BtfSize:     uint32(len(data)),
		BtfLogSize:  uint32(len(log)),
		BtfLogLevel: 1,
	}
	fd, err := bpf(bpfBTFLoad, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(data)
	runtime.KeepAlive(log)
	if err != nil {
		return -1, appendBPFLog(err, log)
	}
	return fd, nil
}

func progLoad(spec *programSpec, license string, insns []byte, objBTF int) (int, error) {
	log := make([]byte, 4<<20)
	licenseBytes := append([]byte(license), 0)
	attr := progLoadAttr{
		ProgType:           spec.progType,
		InsnCnt:            uint32(len(insns) / 8),
		Insns:              bytePtr(insns),
		License:            bytePtr(licenseBytes),
		LogLevel:           1,
		LogSize:            uint32(len(log)),
		LogBuf:             bytePtr(log),
		ProgBtfFd:          uint32(objBTF),
		ExpectedAttachType: spec.expectedAttachType,
		AttachBtfID:        spec.attachBTFID,
	}
	setObjName(&attr.ProgName, spec.name)

	fd, err := bpf(bpfProgLoad, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(insns)
	runtime.KeepAlive(licenseBytes)
	runtime.KeepAlive(log)
	if err != nil {
		return -1, appendBPFLog(err, log)
	}
	return fd, nil
}

func mapUpdate(mapFD int, key uint32, value []byte) error {
	attr := mapElemAttr{
		MapFd: uint32(mapFD),
		Key:   uint64(uintptr(unsafe.Pointer(&key))),
		Value: bytePtr(value),
	}
	_, err := bpf(bpfMapUpdate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

func mapDelete(mapFD int, key uint32) error {
	attr := mapElemAttr{
		MapFd: uint32(mapFD),
		Key:   uint64(uintptr(unsafe.Pointer(&key))),
	}
	_, err := bpf(bpfMapDelete, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(key)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return err
}

func unregisterStructOps(fd int) error {
	return mapDelete(fd, 0)
}

func objPin(fd int, path string) error {
	cpath, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	attr := objPinAttr{
		Pathname: uint64(uintptr(unsafe.Pointer(cpath))),
		BpfFd:    uint32(fd),
	}
	_, err = bpf(bpfObjPin, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(cpath)
	return err
}

func objGet(path string) (int, error) {
	cpath, err := syscall.BytePtrFromString(path)
	if err != nil {
		return -1, err
	}
	attr := objPinAttr{
		Pathname: uint64(uintptr(unsafe.Pointer(cpath))),
	}
	fd, err := bpf(bpfObjGet, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(cpath)
	return fd, err
}

func progAttach(cgroupFD, progFD int, attachType, flags uint32) error {
	attr := progAttachAttr{
		TargetFd:    uint32(cgroupFD),
		AttachBpfFd: uint32(progFD),
		AttachType:  attachType,
		AttachFlags: flags,
	}
	_, err := bpf(bpfProgAttach, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

func progDetach(cgroupFD, progFD int, attachType uint32) error {
	attr := progDetachAttr{
		TargetFd:    uint32(cgroupFD),
		AttachBpfFd: uint32(progFD),
		AttachType:  attachType,
	}
	_, err := bpf(bpfProgDetach, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

func bpf(cmd int, attr unsafe.Pointer, size uintptr) (int, error) {
	sysno, ok := bpfSyscallNumber()
	if !ok {
		return -1, fmt.Errorf("bpf syscall is not defined for linux/%s", runtime.GOARCH)
	}
	r0, _, errno := syscall.Syscall(sysno, uintptr(cmd), uintptr(attr), size)
	if errno != 0 {
		return -1, errno
	}
	return int(r0), nil
}

func bpfSyscallNumber() (uintptr, bool) {
	switch runtime.GOARCH {
	case "386":
		return 357, true
	case "amd64":
		return 321, true
	case "arm":
		return 386, true
	case "arm64", "loong64", "riscv64":
		return 280, true
	case "mips", "mipsle":
		return 4355, true
	case "mips64", "mips64le":
		return 5315, true
	case "ppc64", "ppc64le":
		return 361, true
	case "s390x":
		return 351, true
	default:
		return 0, false
	}
}

func unlinkIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

func bytePtr(data []byte) uint64 {
	if len(data) == 0 {
		return 0
	}
	return uint64(uintptr(unsafe.Pointer(&data[0])))
}

func nativeByteOrder() binary.ByteOrder {
	var value uint16 = 0x0102
	if *(*byte)(unsafe.Pointer(&value)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func nativeEndianIsBig() bool {
	return byteOrderIsBig(nativeByteOrder())
}

func byteOrderIsBig(order binary.ByteOrder) bool {
	var buf [2]byte
	order.PutUint16(buf[:], 0x0102)
	return buf[0] == 0x01
}

func btfByteOrder(data []byte, section string) (binary.ByteOrder, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("%s data is too short", section)
	}
	switch {
	case binary.LittleEndian.Uint16(data[0:2]) == btfMagic:
		return binary.LittleEndian, nil
	case binary.BigEndian.Uint16(data[0:2]) == btfMagic:
		return binary.BigEndian, nil
	default:
		return nil, fmt.Errorf("invalid %s magic %#x", section, binary.LittleEndian.Uint16(data[0:2]))
	}
}

func setObjName(dst *[16]byte, name string) {
	for i := range dst {
		dst[i] = 0
	}
	copy(dst[:len(dst)-1], name)
}

func appendBPFLog(err error, log []byte) error {
	text := cString(log)
	if text == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, text)
}

func cString(buf []byte) string {
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		buf = buf[:i]
	}
	return strings.TrimSpace(string(buf))
}

func stringFromTable(table []byte, off uint32) string {
	if off >= uint32(len(table)) {
		return ""
	}
	end := off
	for end < uint32(len(table)) && table[end] != 0 {
		end++
	}
	return string(table[off:end])
}

// Clang can emit weak __bpf_trap/.ksyms metadata and zero-sized DATASEC records.
// The loader doesn't use .ksyms, so normalize it enough for kernel BTF_LOAD
// while preserving type ids used by maps and programs.
func sanitizeObjectBTF(data []byte, f *elf.File) ([]byte, error) {
	out := make([]byte, len(data))
	copy(out, data)
	order, err := btfByteOrder(out, "BTF")
	if err != nil {
		return nil, err
	}
	var firstVarID uint32
	return out, walkBTFTypes(out, func(id uint32, record, extra []byte, name string, kind, vlen uint32) error {
		if kind == btfKindFunc && vlen > 1 {
			info := order.Uint32(record[4:8])
			info = (info &^ 0xffff) | 1
			order.PutUint32(record[4:8], info)
		}
		if kind == btfKindVar && firstVarID == 0 {
			firstVarID = id
		}
		if kind == btfKindDatasec && order.Uint32(record[8:12]) == 0 {
			size := uint32(1)
			if name == ".ksyms" {
				size = 32
			}
			if sec := f.Section(name); sec != nil && sec.Size > 0 {
				size = uint32(sec.Size)
			}
			order.PutUint32(record[8:12], size)
		}
		if kind == btfKindDatasec {
			for i := uint32(0); i < vlen; i++ {
				entry := extra[i*12 : i*12+12]
				if name == ".ksyms" && firstVarID != 0 {
					order.PutUint32(entry[0:4], firstVarID)
					order.PutUint32(entry[8:12], 32)
				}
				if order.Uint32(entry[8:12]) == 0 {
					order.PutUint32(entry[8:12], 1)
				}
			}
		}
		return nil
	})
}

func walkBTFTypes(data []byte, fn func(id uint32, record, extra []byte, name string, kind, vlen uint32) error) error {
	if len(data) < 24 {
		return errors.New("BTF data is too short")
	}
	order, err := btfByteOrder(data, "BTF")
	if err != nil {
		return err
	}
	hdrLen := order.Uint32(data[4:8])
	typeOff := order.Uint32(data[8:12])
	typeLen := order.Uint32(data[12:16])
	strOff := order.Uint32(data[16:20])
	strLen := order.Uint32(data[20:24])
	typeStart := hdrLen + typeOff
	typeEnd := typeStart + typeLen
	strStart := hdrLen + strOff
	strEnd := strStart + strLen
	if typeEnd > uint32(len(data)) || strEnd > uint32(len(data)) {
		return errors.New("BTF header points outside data")
	}

	types := data[typeStart:typeEnd]
	stringsData := data[strStart:strEnd]
	for off, id := uint32(0), uint32(1); off < uint32(len(types)); id++ {
		if off+12 > uint32(len(types)) {
			return errors.New("truncated BTF type record")
		}
		record := types[off : off+12]
		info := order.Uint32(record[4:8])
		kind := (info >> 24) & 0x1f
		vlen := info & 0xffff
		name := stringFromTable(stringsData, order.Uint32(record[0:4]))
		off += 12
		extraLen := uint32(0)
		switch kind {
		case btfKindInt:
			extraLen = 4
		case btfKindPtr, btfKindFwd, btfKindTypedef, btfKindVolatile, btfKindConst, btfKindRestrict, btfKindFunc, btfKindFloat, btfKindTypeTag:
		case btfKindArray:
			extraLen = 12
		case btfKindStruct, btfKindUnion:
			extraLen = 12 * vlen
		case btfKindEnum:
			extraLen = 8 * vlen
		case btfKindFuncProto:
			extraLen = 8 * vlen
		case btfKindVar:
			extraLen = 4
		case btfKindDatasec:
			extraLen = 12 * vlen
		case btfKindDeclTag:
			extraLen = 4
		case btfKindEnum64:
			extraLen = 12 * vlen
		default:
			return fmt.Errorf("unsupported BTF kind %d", kind)
		}
		if off+extraLen > uint32(len(types)) {
			return errors.New("BTF type record exceeds type section")
		}
		if err := fn(id, record, types[off:off+extraLen], name, kind, vlen); err != nil {
			return err
		}
		off += extraLen
		if off > uint32(len(types)) {
			return errors.New("BTF type record exceeds type section")
		}
	}
	return nil
}

type btfSpec struct {
	order   binary.ByteOrder
	types   []*btfType
	strings []byte
}

type btfType struct {
	id         uint32
	name       string
	kind       uint32
	size       uint32
	typeID     uint32
	members    []btfMember
	paramCount uint32
	varType    uint32
}

type btfMember struct {
	name      string
	typeID    uint32
	bitOffset uint32
}

type btfHeader struct {
	magic   uint16
	version uint8
	flags   uint8
	hdrLen  uint32
	typeOff uint32
	typeLen uint32
	strOff  uint32
	strLen  uint32
}

func parseBTF(data []byte) (*btfSpec, error) {
	if len(data) < 24 {
		return nil, errors.New("BTF data is too short")
	}
	order, err := btfByteOrder(data, "BTF")
	if err != nil {
		return nil, err
	}
	hdr := btfHeader{
		magic:   order.Uint16(data[0:2]),
		version: data[2],
		flags:   data[3],
		hdrLen:  order.Uint32(data[4:8]),
		typeOff: order.Uint32(data[8:12]),
		typeLen: order.Uint32(data[12:16]),
		strOff:  order.Uint32(data[16:20]),
		strLen:  order.Uint32(data[20:24]),
	}
	if hdr.magic != btfMagic {
		return nil, fmt.Errorf("invalid BTF magic %#x", hdr.magic)
	}
	if hdr.version != 1 {
		return nil, fmt.Errorf("unsupported BTF version %d", hdr.version)
	}
	typeStart := hdr.hdrLen + hdr.typeOff
	typeEnd := typeStart + hdr.typeLen
	strStart := hdr.hdrLen + hdr.strOff
	strEnd := strStart + hdr.strLen
	if typeEnd > uint32(len(data)) || strEnd > uint32(len(data)) {
		return nil, errors.New("BTF header points outside data")
	}

	spec := &btfSpec{order: order, strings: data[strStart:strEnd]}
	types := data[typeStart:typeEnd]
	for off, id := uint32(0), uint32(1); off < uint32(len(types)); id++ {
		if off+12 > uint32(len(types)) {
			return nil, errors.New("truncated BTF type record")
		}
		nameOff := order.Uint32(types[off : off+4])
		info := order.Uint32(types[off+4 : off+8])
		sizeType := order.Uint32(types[off+8 : off+12])
		off += 12

		kind := (info >> 24) & 0x1f
		vlen := info & 0xffff
		t := &btfType{
			id:     id,
			name:   spec.string(nameOff),
			kind:   kind,
			size:   sizeType,
			typeID: sizeType,
		}

		switch kind {
		case btfKindInt:
			off += 4
		case btfKindPtr, btfKindFwd, btfKindTypedef, btfKindVolatile, btfKindConst, btfKindRestrict, btfKindFunc, btfKindFloat, btfKindTypeTag:
		case btfKindArray:
			off += 12
		case btfKindStruct, btfKindUnion:
			t.members = make([]btfMember, 0, vlen)
			for i := uint32(0); i < vlen; i++ {
				if off+12 > uint32(len(types)) {
					return nil, fmt.Errorf("truncated BTF members for %s", t.name)
				}
				t.members = append(t.members, btfMember{
					name:      spec.string(order.Uint32(types[off : off+4])),
					typeID:    order.Uint32(types[off+4 : off+8]),
					bitOffset: order.Uint32(types[off+8:off+12]) & 0x00ffffff,
				})
				off += 12
			}
		case btfKindEnum:
			off += 8 * vlen
		case btfKindFuncProto:
			if off+8*vlen > uint32(len(types)) {
				return nil, fmt.Errorf("truncated BTF function prototype for %s", t.name)
			}
			t.paramCount = vlen
			off += 8 * vlen
		case btfKindVar:
			t.varType = sizeType
			off += 4
		case btfKindDatasec:
			off += 12 * vlen
		case btfKindDeclTag:
			off += 4
		case btfKindEnum64:
			off += 12 * vlen
		default:
			return nil, fmt.Errorf("unsupported BTF kind %d", kind)
		}
		if off > uint32(len(types)) {
			return nil, errors.New("BTF type record exceeds type section")
		}
		spec.types = append(spec.types, t)
	}
	return spec, nil
}

func (s *btfSpec) string(off uint32) string {
	return stringFromTable(s.strings, off)
}

func (s *btfSpec) typeByID(id uint32) *btfType {
	if id == 0 || id > uint32(len(s.types)) {
		return nil
	}
	return s.types[id-1]
}

func (s *btfSpec) find(kind uint32, name string) *btfType {
	for _, typ := range s.types {
		if typ.kind == kind && typ.name == name {
			return typ
		}
	}
	return nil
}

func (s *btfSpec) varTypeID(name string) (uint32, error) {
	variable := s.find(btfKindVar, name)
	if variable == nil {
		return 0, fmt.Errorf("BTF is missing var %s", name)
	}
	return variable.varType, nil
}

func (s *btfSpec) mapTypeIDs(name string) (keyTypeID, valueTypeID, valueSize uint32, err error) {
	mapTypeID, err := s.varTypeID(name)
	if err != nil {
		return 0, 0, 0, err
	}
	mapType := s.typeByID(mapTypeID)
	if mapType == nil || mapType.kind != btfKindStruct {
		return 0, 0, 0, fmt.Errorf("BTF var %s is not a map definition struct", name)
	}

	keyMember := mapType.member("key")
	valueMember := mapType.member("value")
	if keyMember == nil || valueMember == nil {
		return 0, 0, 0, fmt.Errorf("BTF map %s is missing key or value member", name)
	}

	keyTypeID = s.resolvePtr(keyMember.typeID)
	valueTypeID = s.resolvePtr(valueMember.typeID)
	if keyTypeID == 0 || valueTypeID == 0 {
		return 0, 0, 0, fmt.Errorf("BTF map %s key/value are not pointer-encoded __type members", name)
	}
	valueSize, err = s.sizeof(valueTypeID)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("BTF map %s value size: %w", name, err)
	}
	return keyTypeID, valueTypeID, valueSize, nil
}

func (s *btfSpec) resolvePtr(typeID uint32) uint32 {
	typ := s.typeByID(typeID)
	if typ != nil && typ.kind == btfKindPtr {
		return typ.typeID
	}
	return 0
}

func (s *btfSpec) sizeof(typeID uint32) (uint32, error) {
	typ := s.typeByID(typeID)
	if typ == nil {
		return 0, fmt.Errorf("invalid type id %d", typeID)
	}
	switch typ.kind {
	case btfKindInt, btfKindStruct, btfKindUnion, btfKindEnum, btfKindFloat:
		return typ.size, nil
	case btfKindPtr:
		return 8, nil
	case btfKindTypedef, btfKindVolatile, btfKindConst, btfKindRestrict, btfKindTypeTag:
		return s.sizeof(typ.typeID)
	default:
		return 0, fmt.Errorf("unsupported sizeof kind %d for %s", typ.kind, typ.name)
	}
}

func (s *btfSpec) structOpsInfo(innerName string) (*structOpsInfo, error) {
	wrapperName := "bpf_struct_ops_" + innerName
	wrapper := s.find(btfKindStruct, wrapperName)
	inner := s.find(btfKindStruct, innerName)
	if inner == nil {
		return nil, fmt.Errorf("kernel BTF is missing struct %s", innerName)
	}
	if wrapper == nil {
		return nil, fmt.Errorf("kernel BTF is missing struct %s; Linux 6.10 or newer is required", wrapperName)
	}

	info := &structOpsInfo{
		innerTypeID: inner.id,
		members:     make(map[string]structOpsMember),
	}
	data := wrapper.member("data")
	if data == nil {
		return nil, fmt.Errorf("kernel BTF struct %s is missing data member", wrapperName)
	}
	info.valueTypeID = wrapper.id
	info.valueSize = wrapper.size
	info.dataOffset = data.bitOffset / 8

	for i, member := range inner.members {
		info.members[member.name] = structOpsMember{
			index:  uint32(i),
			offset: member.bitOffset / 8,
			typeID: member.typeID,
		}
	}
	return info, nil
}

func (s *btfSpec) requireTCP610(ops *structOpsInfo) error {
	member, ok := ops.members["cong_control"]
	if !ok {
		return errors.New("kernel tcp_congestion_ops is missing member cong_control")
	}
	proto := s.funcProto(member.typeID)
	if proto == nil {
		return errors.New("kernel tcp_congestion_ops.cong_control is not a function pointer")
	}
	if proto.paramCount != 4 {
		return fmt.Errorf("kernel tcp_congestion_ops.cong_control has %d parameters; Linux 6.10 or newer is required", proto.paramCount)
	}
	return nil
}

func (s *btfSpec) funcProto(typeID uint32) *btfType {
	typ := s.resolveType(typeID)
	if typ != nil && typ.kind == btfKindPtr {
		typ = s.resolveType(typ.typeID)
	}
	if typ != nil && typ.kind == btfKindFuncProto {
		return typ
	}
	return nil
}

func (s *btfSpec) resolveType(typeID uint32) *btfType {
	for {
		typ := s.typeByID(typeID)
		if typ == nil {
			return nil
		}
		switch typ.kind {
		case btfKindTypedef, btfKindVolatile, btfKindConst, btfKindRestrict, btfKindTypeTag:
			typeID = typ.typeID
		default:
			return typ
		}
	}
}

func (t *btfType) member(name string) *btfMember {
	for i := range t.members {
		if t.members[i].name == name {
			return &t.members[i]
		}
	}
	return nil
}

func (t *btfType) matchCoreMember(name string, fallbackIndex uint32) *btfMember {
	if name != "" {
		return t.member(name)
	}
	if fallbackIndex < uint32(len(t.members)) {
		return &t.members[fallbackIndex]
	}
	return nil
}

func btfKindName(kind uint32) string {
	switch kind {
	case btfKindInt:
		return "int"
	case btfKindPtr:
		return "ptr"
	case btfKindArray:
		return "array"
	case btfKindStruct:
		return "struct"
	case btfKindUnion:
		return "union"
	case btfKindEnum:
		return "enum"
	case btfKindFwd:
		return "fwd"
	case btfKindTypedef:
		return "typedef"
	case btfKindVolatile:
		return "volatile"
	case btfKindConst:
		return "const"
	case btfKindRestrict:
		return "restrict"
	case btfKindFunc:
		return "func"
	case btfKindFuncProto:
		return "func_proto"
	case btfKindVar:
		return "var"
	case btfKindDatasec:
		return "datasec"
	case btfKindFloat:
		return "float"
	case btfKindDeclTag:
		return "decl_tag"
	case btfKindTypeTag:
		return "type_tag"
	case btfKindEnum64:
		return "enum64"
	default:
		return fmt.Sprintf("kind%d", kind)
	}
}
