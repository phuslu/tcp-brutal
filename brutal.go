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

	bpfObjectLittleEndianName       = "brutal_linux_bpfel.o"
	bpfObjectBigEndianName          = "brutal_linux_bpfeb.o"
	bpfObjectLegacyLittleEndianName = "brutal_legacy_linux_bpfel.o"
	bpfObjectLegacyBigEndianName    = "brutal_legacy_linux_bpfeb.o"
	structOpsPinPath                = defaultPinRoot + "/brutal_cc"
	setsockoptPinPath               = defaultPinRoot + "/brutal_setsockopt"
)

const (
	bpfMapCreate    = 0
	bpfMapUpdate    = 2
	bpfMapDelete    = 3
	bpfProgLoad     = 5
	bpfObjPin       = 6
	bpfObjGet       = 7
	bpfProgDetach   = 9
	bpfProgGetFD    = 13
	bpfMapGetFD     = 14
	bpfObjGetInfo   = 15
	bpfBTFLoad      = 18
	bpfLinkCreate   = 28
	bpfLinkDetach   = 34
	bpfMapTypeSk    = 24
	bpfMapTypeOps   = 26
	bpfProgCgrpOpt  = 25
	bpfProgOps      = 27
	bpfAttachSetOpt = 22
	bpfAttachOps    = 44
	bpfLinkCgroup   = 3
	bpfLinkOps      = 9
	bpfFSMagic      = uint32(0xcafe4a11)
	bpfFNoPrealloc  = 1
	bpfFLink        = 1 << 13
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
	bpfCoreFieldByteSize   = 1
	bpfCoreFieldExists     = 2
	bpfCoreFieldSigned     = 3
	bpfCoreFieldLShiftU64  = 4
	bpfCoreFieldRShiftU64  = 5
	bpfCoreTypeIDLocal     = 6
	bpfCoreTypeIDTarget    = 7
	bpfCoreTypeExists      = 8
	bpfCoreTypeSize        = 9
	bpfCoreEnumvalExists   = 10
	bpfCoreEnumvalValue    = 11
	bpfCoreTypeMatches     = 12

	btfMagic     = 0xeb9f
	btfKindFlag  = uint32(1 << 31)
	btfIntSigned = 1
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
	fds  []int
	pins []string
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

type pinnedLinkState struct {
	exists bool
	valid  bool
	reason string
}

type bpfFDKind uint8

const (
	bpfFDUnknown bpfFDKind = iota
	bpfFDMap
	bpfFDProgram
	bpfFDLink
)

type installationState struct {
	algorithm  bool
	structOps  pinnedLinkState
	setsockopt pinnedLinkState
}

func (s installationState) complete() bool {
	return s.algorithm && s.structOps.valid && s.setsockopt.valid
}

func (s installationState) empty() bool {
	return !s.algorithm && !s.structOps.exists && !s.setsockopt.exists
}

func (s installationState) summary() string {
	parts := make([]string, 0, 3)
	if s.algorithm {
		parts = append(parts, "algorithm is registered")
	} else {
		parts = append(parts, "algorithm is not registered")
	}
	appendPin := func(name string, pin pinnedLinkState) {
		switch {
		case !pin.exists:
			parts = append(parts, name+" link is missing")
		case !pin.valid:
			parts = append(parts, name+" link is invalid: "+pin.reason)
		default:
			parts = append(parts, name+" link is valid")
		}
	}
	appendPin("struct_ops", s.structOps)
	appendPin("setsockopt", s.setsockopt)
	return strings.Join(parts, "; ")
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

type progDetachAttr struct {
	TargetFd         uint32
	AttachBpfFd      uint32
	AttachType       uint32
	AttachFlags      uint32
	_                uint32
	RelativeFdOrID   uint32
	ExpectedRevision uint64
}

type linkCreateAttr struct {
	ProgOrMapFd uint32
	TargetFd    uint32
	AttachType  uint32
	Flags       uint32
	Extra       [48]byte
}

type linkDetachAttr struct {
	LinkFd uint32
}

type objInfoAttr struct {
	BpfFd   uint32
	InfoLen uint32
	Info    uint64
}

type idAttr struct {
	ID        uint32
	NextID    uint32
	OpenFlags uint32
}

type bpfLinkInfo struct {
	Type   uint32
	ID     uint32
	ProgID uint32
	_      uint32
	Data   [64]byte
}

type bpfProgInfo struct {
	Type            uint32
	ID              uint32
	Tag             [8]byte
	JitedProgLen    uint32
	XlatedProgLen   uint32
	JitedProgInsns  uint64
	XlatedProgInsns uint64
	LoadTime        uint64
	CreatedByUID    uint32
	NrMapIDs        uint32
	MapIDs          uint64
	Name            [16]byte
}

type bpfMapInfo struct {
	Type       uint32
	ID         uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
	Name       [16]byte
}

func Load() error {
	return LoadWithOptions(Options{})
}

func (opts Options) Load() error {
	return LoadWithOptions(opts)
}

func LoadWithOptions(opts Options) error {
	opts = opts.withDefaults()
	if err := ensurePinRoot(); err != nil {
		return err
	}

	state, err := inspectInstallation(opts)
	if err != nil {
		return fmt.Errorf("inspect existing TCP Brutal installation: %w", err)
	}
	if opts.Force {
		if !state.empty() {
			if err := unload(opts); err != nil {
				return fmt.Errorf("remove existing TCP Brutal installation: %w", err)
			}
			state, err = inspectInstallation(opts)
			if err != nil {
				return fmt.Errorf("verify TCP Brutal cleanup: %w", err)
			}
			if !state.empty() {
				return fmt.Errorf("TCP Brutal state remains after forced cleanup: %s", state.summary())
			}
		}
	} else {
		if state.complete() {
			return nil
		}
		if !state.empty() {
			return fmt.Errorf("incomplete TCP Brutal installation: %s; retry with Force to repair managed pins", state.summary())
		}
	}

	if err := removeMemlockLimit(); err != nil {
		return fmt.Errorf("raise memlock rlimit: %w", err)
	}

	loaded, err := loadBPF(opts)
	if err != nil {
		return err
	}
	loaded.close()

	state, err = inspectInstallation(opts)
	if err == nil && state.complete() {
		return nil
	}
	cleanupErr := unload(opts)
	if err != nil {
		if cleanupErr != nil {
			return fmt.Errorf("verify loaded TCP Brutal installation: %v; cleanup: %w", err, cleanupErr)
		}
		return fmt.Errorf("verify loaded TCP Brutal installation: %w", err)
	}
	if cleanupErr != nil {
		return fmt.Errorf("loaded TCP Brutal installation is incomplete: %s; cleanup: %w", state.summary(), cleanupErr)
	}
	return fmt.Errorf("loaded TCP Brutal installation is incomplete: %s", state.summary())
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
	return IsLoadedWithOptions(Options{})
}

func IsLoadedWithOptions(opts Options) bool {
	state, err := inspectInstallation(opts.withDefaults())
	return err == nil && state.complete()
}

func (opts Options) IsLoaded() bool {
	return IsLoadedWithOptions(opts)
}

func algorithmAvailable() (bool, error) {
	data, err := os.ReadFile(tcpAvailableCongestionControl)
	if err != nil {
		return false, err
	}
	for _, algo := range strings.Fields(string(data)) {
		if algo == "brutal" {
			return true, nil
		}
	}
	return false, nil
}

func (opts Options) withDefaults() Options {
	if opts.CgroupPath == "" {
		opts.CgroupPath = defaultCgroupPath
	}
	return opts
}

func inspectInstallation(opts Options) (installationState, error) {
	var state installationState
	var err error
	state.algorithm, err = algorithmAvailable()
	if err != nil {
		return state, err
	}
	state.structOps, err = inspectStructOpsLink(structOpsPinPath)
	if err != nil {
		return state, err
	}
	state.setsockopt, err = inspectSetsockoptLink(setsockoptPinPath, opts.CgroupPath)
	if err != nil {
		return state, err
	}
	return state, nil
}

func inspectStructOpsLink(path string) (pinnedLinkState, error) {
	state, info, err := inspectPinnedLink(path, bpfLinkOps)
	if err != nil || !state.valid {
		return state, err
	}

	mapID := nativeByteOrder().Uint32(info.Data[:4])
	if mapID == 0 {
		state.valid = false
		state.reason = "link has no struct_ops map"
		return state, nil
	}
	fd, err := mapGetFDByID(mapID)
	if err != nil {
		return state, fmt.Errorf("open struct_ops map id %d: %w", mapID, err)
	}
	defer syscall.Close(fd)
	mapInfo, err := getMapInfo(fd)
	if err != nil {
		return state, fmt.Errorf("inspect struct_ops map id %d: %w", mapID, err)
	}
	if mapInfo.Type != bpfMapTypeOps {
		state.valid = false
		state.reason = fmt.Sprintf("map id %d has type %d", mapID, mapInfo.Type)
	} else if mapInfo.MapFlags&bpfFLink == 0 {
		state.valid = false
		state.reason = fmt.Sprintf("map id %d is not link-managed", mapID)
	} else if cString(mapInfo.Name[:]) != "brutal" {
		state.valid = false
		state.reason = fmt.Sprintf("map id %d has name %q", mapID, cString(mapInfo.Name[:]))
	}
	return state, nil
}

func validateStructOpsLinkInfo(info bpfLinkInfo) error {
	if info.Type != bpfLinkOps {
		return fmt.Errorf("link type is %d, want %d", info.Type, bpfLinkOps)
	}
	mapID := nativeByteOrder().Uint32(info.Data[:4])
	if mapID == 0 {
		// A successfully detached struct_ops link stays pinnable but no longer
		// reports a map. It is safe to remove that defunct managed pin.
		return nil
	}
	fd, err := mapGetFDByID(mapID)
	if err != nil {
		return fmt.Errorf("open struct_ops map id %d: %w", mapID, err)
	}
	defer syscall.Close(fd)
	mapInfo, err := getMapInfo(fd)
	if err != nil {
		return fmt.Errorf("inspect struct_ops map id %d: %w", mapID, err)
	}
	if mapInfo.Type != bpfMapTypeOps || mapInfo.MapFlags&bpfFLink == 0 || cString(mapInfo.Name[:]) != "brutal" {
		return fmt.Errorf("map id %d has type %d, name %q, flags %#x", mapID, mapInfo.Type, cString(mapInfo.Name[:]), mapInfo.MapFlags)
	}
	return nil
}

func inspectSetsockoptLink(path, cgroupPath string) (pinnedLinkState, error) {
	state, info, err := inspectPinnedLink(path, bpfLinkCgroup)
	if err != nil || !state.valid {
		return state, err
	}

	order := nativeByteOrder()
	cgroupID := order.Uint64(info.Data[:8])
	attachType := order.Uint32(info.Data[8:12])
	if attachType != bpfAttachSetOpt {
		state.valid = false
		state.reason = fmt.Sprintf("attach type is %d, want %d", attachType, bpfAttachSetOpt)
		return state, nil
	}
	var stat syscall.Stat_t
	if err := syscall.Stat(cgroupPath, &stat); err != nil {
		return state, fmt.Errorf("stat cgroup %s: %w", cgroupPath, err)
	}
	if cgroupID != stat.Ino {
		state.valid = false
		state.reason = fmt.Sprintf("cgroup id is %d, want %d for %s", cgroupID, stat.Ino, cgroupPath)
		return state, nil
	}
	if info.ProgID == 0 {
		state.valid = false
		state.reason = "link has no program"
		return state, nil
	}
	fd, err := progGetFDByID(info.ProgID)
	if err != nil {
		return state, fmt.Errorf("open setsockopt program id %d: %w", info.ProgID, err)
	}
	defer syscall.Close(fd)
	progInfo, err := getProgInfo(fd)
	if err != nil {
		return state, fmt.Errorf("inspect setsockopt program id %d: %w", info.ProgID, err)
	}
	if progInfo.Type != bpfProgCgrpOpt {
		state.valid = false
		state.reason = fmt.Sprintf("program id %d has type %d", info.ProgID, progInfo.Type)
	} else if cString(progInfo.Name[:]) != bpfKernelName("brutal_setsockopt") {
		state.valid = false
		state.reason = fmt.Sprintf("program id %d has name %q", info.ProgID, cString(progInfo.Name[:]))
	}
	return state, nil
}

func validateSetsockoptLinkInfo(info bpfLinkInfo) error {
	if info.Type != bpfLinkCgroup {
		return fmt.Errorf("link type is %d, want %d", info.Type, bpfLinkCgroup)
	}
	attachType := nativeByteOrder().Uint32(info.Data[8:12])
	if attachType != bpfAttachSetOpt {
		return fmt.Errorf("attach type is %d, want %d", attachType, bpfAttachSetOpt)
	}
	if info.ProgID == 0 {
		if nativeByteOrder().Uint64(info.Data[:8]) == 0 {
			// A defunct cgroup link has neither a target nor a program.
			return nil
		}
		return errors.New("link has no program")
	}
	fd, err := progGetFDByID(info.ProgID)
	if err != nil {
		return fmt.Errorf("open setsockopt program id %d: %w", info.ProgID, err)
	}
	defer syscall.Close(fd)
	progInfo, err := getProgInfo(fd)
	if err != nil {
		return fmt.Errorf("inspect setsockopt program id %d: %w", info.ProgID, err)
	}
	if progInfo.Type != bpfProgCgrpOpt || cString(progInfo.Name[:]) != bpfKernelName("brutal_setsockopt") {
		return fmt.Errorf("program id %d has type %d and name %q", info.ProgID, progInfo.Type, cString(progInfo.Name[:]))
	}
	return nil
}

func inspectPinnedLink(path string, expectedType uint32) (pinnedLinkState, bpfLinkInfo, error) {
	var state pinnedLinkState
	var info bpfLinkInfo
	fd, err := objGet(path)
	if errors.Is(err, syscall.ENOENT) {
		return state, info, nil
	}
	if err != nil {
		return state, info, fmt.Errorf("open pinned object %s: %w", path, err)
	}
	defer syscall.Close(fd)
	state.exists = true
	kind, err := bpfObjectKind(fd)
	if err != nil {
		return state, info, fmt.Errorf("identify pinned object %s: %w", path, err)
	}
	if kind != bpfFDLink {
		state.reason = fmt.Sprintf("object kind is %s, want link", kind)
		return state, info, nil
	}
	info, err = getLinkInfo(fd)
	if err != nil {
		return state, info, fmt.Errorf("inspect pinned object %s: %w", path, err)
	}
	if info.Type != expectedType {
		state.reason = fmt.Sprintf("object type is %d, want link type %d", info.Type, expectedType)
		return state, info, nil
	}
	state.valid = true
	return state, info, nil
}

func (kind bpfFDKind) String() string {
	switch kind {
	case bpfFDMap:
		return "map"
	case bpfFDProgram:
		return "program"
	case bpfFDLink:
		return "link"
	default:
		return "unknown"
	}
}

func bpfKernelName(name string) string {
	var value [16]byte
	setObjName(&value, name)
	return cString(value[:])
}

func bpfObjectKind(fd int) (bpfFDKind, error) {
	data, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return bpfFDUnknown, fmt.Errorf("read BPF fdinfo for fd %d: %w", fd, err)
	}
	kind, err := parseBPFObjectKind(data)
	if err != nil {
		return bpfFDUnknown, fmt.Errorf("identify BPF fd %d: %w", fd, err)
	}
	return kind, nil
}

func parseBPFObjectKind(data []byte) (bpfFDKind, error) {
	kind := bpfFDUnknown
	for _, line := range strings.Split(string(data), "\n") {
		var found bpfFDKind
		switch {
		case strings.HasPrefix(line, "map_type:\t"):
			found = bpfFDMap
		case strings.HasPrefix(line, "prog_type:\t"):
			found = bpfFDProgram
		case strings.HasPrefix(line, "link_type:\t"):
			found = bpfFDLink
		default:
			continue
		}
		if kind != bpfFDUnknown && kind != found {
			return bpfFDUnknown, errors.New("fdinfo contains conflicting BPF object kinds")
		}
		kind = found
	}
	if kind == bpfFDUnknown {
		return bpfFDUnknown, errors.New("fdinfo contains no BPF object type")
	}
	return kind, nil
}

func loadBPF(opts Options) (_ *loadedBPF, err error) {
	kernelBTF, err := loadKernelBTF()
	if err != nil {
		return nil, err
	}

	opsInfo, err := kernelBTF.structOpsInfo("tcp_congestion_ops")
	if err != nil {
		return nil, err
	}
	congControlParams, err := kernelBTF.tcpCongControlParamCount(opsInfo)
	if err != nil {
		return nil, err
	}

	objBytes, objName, err := selectObject(congControlParams)
	if err != nil {
		return nil, err
	}

	obj, err := parseBPFObject(objBytes, objName)
	if err != nil {
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
			loaded.rollback()
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

	value, err := obj.structOpsValue(opsInfo, kernelBTF, programs)
	if err != nil {
		return nil, err
	}
	if err = mapUpdate(structMap, 0, value); err != nil {
		return nil, fmt.Errorf("prepare struct_ops brutal: %w", err)
	}

	structLink, err := linkCreate(structMap, 0, bpfAttachOps, 0)
	if err != nil {
		return nil, fmt.Errorf("attach struct_ops brutal: %w", err)
	}
	loaded.fds = append(loaded.fds, structLink)

	setsockoptLink, err := attachSetsockopt(programs["brutal_setsockopt"], opts.CgroupPath)
	if err != nil {
		return nil, err
	}
	loaded.fds = append(loaded.fds, setsockoptLink)

	if err = objPin(structLink, structOpsPinPath); err != nil {
		return nil, fmt.Errorf("pin struct_ops link %s: %w", structOpsPinPath, err)
	}
	loaded.pins = append(loaded.pins, structOpsPinPath)
	if err = objPin(setsockoptLink, setsockoptPinPath); err != nil {
		return nil, fmt.Errorf("pin cgroup setsockopt link %s: %w", setsockoptPinPath, err)
	}
	loaded.pins = append(loaded.pins, setsockoptPinPath)

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

func (l *loadedBPF) rollback() {
	if l == nil {
		return
	}
	for i := len(l.pins) - 1; i >= 0; i-- {
		_ = unlinkIfExists(l.pins[i])
	}
	l.pins = nil
	l.close()
}

func selectObject(congControlParamCount int) ([]byte, string, error) {
	var legacy bool
	switch congControlParamCount {
	case 2:
		legacy = true
	case 4:
	case 0:

		return nil, "", errors.New("kernel tcp_congestion_ops.cong_control has no parameters")
	default:
		return nil, "", fmt.Errorf("kernel tcp_congestion_ops.cong_control has %d parameters; Linux 6.0 or newer with a supported tcp_congestion_ops ABI is required", congControlParamCount)
	}

	name := bpfObjectName(nativeEndianIsBig(), legacy)
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

func bpfObjectName(bigEndian, legacy bool) string {
	if legacy {
		if bigEndian {
			return bpfObjectLegacyBigEndianName
		}
		return bpfObjectLegacyLittleEndianName
	}
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
		value, err := resolveCoreReloc(localBTF, targetBTF, rel, order)
		if err != nil {
			return fmt.Errorf("resolve %q at instruction offset %#x: %w", rel.access, rel.insnOffset, err)
		}
		if err := patchCoreReloc(insns, rel.insnOffset, value, order); err != nil {
			return err
		}
	}
	return nil
}

func isSupportedFieldCoreReloc(kind uint32) bool {
	switch kind {
	case bpfCoreFieldByteOffset, bpfCoreFieldByteSize, bpfCoreFieldSigned,
		bpfCoreFieldExists, bpfCoreFieldLShiftU64, bpfCoreFieldRShiftU64:
		return true
	default:
		return false
	}
}

func resolveCoreReloc(localBTF, targetBTF *btfSpec, rel coreReloc, order binary.ByteOrder) (uint64, error) {
	if isSupportedFieldCoreReloc(rel.kind) {
		return resolveCoreFieldReloc(localBTF, targetBTF, rel.typeID, rel.access, rel.kind, order)
	}

	switch rel.kind {
	case bpfCoreTypeIDLocal:
		if err := validateCoreTypeAccess(rel.access); err != nil {
			return 0, err
		}
		if localBTF.typeByID(rel.typeID) == nil {
			return 0, fmt.Errorf("local BTF type id %d not found", rel.typeID)
		}
		return uint64(rel.typeID), nil
	case bpfCoreTypeIDTarget, bpfCoreTypeExists, bpfCoreTypeSize, bpfCoreTypeMatches:
		return resolveCoreTypeReloc(localBTF, targetBTF, rel.typeID, rel.access, rel.kind)
	case bpfCoreEnumvalExists, bpfCoreEnumvalValue:
		return resolveCoreEnumReloc(localBTF, targetBTF, rel.typeID, rel.access, rel.kind)
	default:
		return 0, fmt.Errorf("unsupported CO-RE relocation kind %d", rel.kind)
	}
}

type coreField struct {
	typeID         uint32
	bitOffset      uint32
	bitfieldOffset uint32
	bitfieldSize   uint32
	loadSize       uint32
}

var errCoreTargetNotFound = errors.New("CO-RE target not found")

func resolveCoreFieldReloc(localBTF, targetBTF *btfSpec, typeID uint32, access string, kind uint32, order binary.ByteOrder) (uint64, error) {
	field, err := resolveCoreField(localBTF, targetBTF, typeID, access)
	if err != nil {
		if kind == bpfCoreFieldExists && errors.Is(err, errCoreTargetNotFound) {
			return 0, nil
		}
		return 0, err
	}

	switch kind {
	case bpfCoreFieldExists:
		return 1, nil

	case bpfCoreFieldByteOffset:
		if field.bitfieldSize > 0 {
			offset, err := targetBTF.coreBitfieldByteOffset(field)
			if err != nil {
				return 0, err
			}
			return uint64(offset), nil
		}
		if field.bitOffset%8 != 0 {
			return 0, fmt.Errorf("resolved bit offset %d is not byte aligned", field.bitOffset)
		}
		return uint64(field.bitOffset / 8), nil

	case bpfCoreFieldByteSize:
		size, err := targetBTF.sizeof(field.typeID)
		if err != nil {
			return 0, err
		}
		return uint64(size), nil

	case bpfCoreFieldSigned:
		value, err := targetBTF.coreFieldSigned(field.typeID)
		return uint64(value), err

	case bpfCoreFieldLShiftU64:
		size, err := targetBTF.coreFieldBitSize(field)
		if err != nil {
			return 0, err
		}
		if order == binary.LittleEndian {
			if field.bitfieldOffset+size > 64 {
				return 0, fmt.Errorf("bitfield exceeds u64 extraction width: offset %d size %d", field.bitfieldOffset, size)
			}
			return uint64(64 - field.bitfieldOffset - size), nil
		}
		loadSize := field.loadSize
		if loadSize == 0 {
			loadSize, err = targetBTF.sizeof(field.typeID)
			if err != nil {
				return 0, err
			}
		}
		loadBits := loadSize * 8
		if loadBits > 64 || field.bitfieldOffset > loadBits {
			return 0, fmt.Errorf("invalid big-endian bitfield extraction: offset %d load bits %d", field.bitfieldOffset, loadBits)
		}
		return uint64(64 - loadBits + field.bitfieldOffset), nil

	case bpfCoreFieldRShiftU64:
		size, err := targetBTF.coreFieldBitSize(field)
		if err != nil {
			return 0, err
		}
		if size > 64 {
			return 0, fmt.Errorf("field bit size %d exceeds u64 extraction width", size)
		}
		return uint64(64 - size), nil

	default:
		return 0, fmt.Errorf("unsupported CO-RE relocation kind %d", kind)
	}
}

func resolveCoreField(localBTF, targetBTF *btfSpec, typeID uint32, access string) (coreField, error) {
	accessors, err := parseCoreAccess(access)
	if err != nil {
		return coreField{}, err
	}
	if len(accessors) == 0 {
		return coreField{}, fmt.Errorf("empty access path %q", access)
	}

	localType := localBTF.resolveType(typeID)
	if localType == nil {
		return coreField{}, fmt.Errorf("local BTF type id %d not found", typeID)
	}
	targetType := targetBTF.findCoreTargetType(localType)
	if targetType == nil {
		return coreField{}, fmt.Errorf("%w: target BTF is missing %s %q", errCoreTargetNotFound, btfKindName(localType.kind), localType.name)
	}
	if !coreFieldsCompatible(localBTF, targetBTF, localType.id, targetType.id, make(map[uint64]bool)) {
		return coreField{}, fmt.Errorf("%w: target %s %q is incompatible", errCoreTargetNotFound, btfKindName(targetType.kind), targetType.name)
	}

	localSize, err := localBTF.sizeof(localType.id)
	if err != nil {
		return coreField{}, fmt.Errorf("size of local root type: %w", err)
	}
	if _, err := coreArrayBitOffset(accessors[0], localSize); err != nil {
		return coreField{}, fmt.Errorf("local root array access: %w", err)
	}
	targetSize, err := targetBTF.sizeof(targetType.id)
	if err != nil {
		return coreField{}, fmt.Errorf("size of target root type: %w", err)
	}
	rootOffset, err := coreArrayBitOffset(accessors[0], targetSize)
	if err != nil {
		return coreField{}, fmt.Errorf("target root array access: %w", err)
	}

	field := coreField{typeID: targetType.id, bitOffset: rootOffset}
	for position, index := range accessors[1:] {
		localType = localBTF.resolveType(localType.id)
		targetType = targetBTF.resolveType(targetType.id)
		if localType == nil || targetType == nil {
			return coreField{}, errors.New("invalid BTF type while resolving access path")
		}

		switch localType.kind {
		case btfKindStruct, btfKindUnion:
			if index >= uint32(len(localType.members)) {
				return coreField{}, fmt.Errorf("member index %d is outside local type %q", index, localType.name)
			}
			localMember := localType.members[index]
			if localMember.name == "" {
				localType = localBTF.resolveType(localMember.typeID)
				if localType == nil || (localType.kind != btfKindStruct && localType.kind != btfKindUnion) {
					return coreField{}, errors.New("anonymous local member is not a struct or union")
				}
				continue
			}
			if targetType.kind != btfKindStruct && targetType.kind != btfKindUnion {
				return coreField{}, fmt.Errorf("%w: target type %q is not a struct or union", errCoreTargetNotFound, targetType.name)
			}
			targetMember, err := targetBTF.findCoreMember(targetType, localMember.name)
			if err != nil {
				return coreField{}, err
			}
			field.bitOffset, err = addCoreBitOffset(field.bitOffset, targetMember.bitOffset)
			if err != nil {
				return coreField{}, err
			}
			field.typeID = targetMember.typeID
			field.bitfieldSize = targetMember.bitfieldSize
			field.bitfieldOffset = 0
			field.loadSize = 0
			localType = localBTF.resolveType(localMember.typeID)
			targetType = targetBTF.resolveType(targetMember.typeID)
			if (localMember.bitfieldSize != 0 || targetMember.bitfieldSize != 0) && position+1 < len(accessors[1:]) {
				return coreField{}, errors.New("cannot descend into a bitfield")
			}

		case btfKindArray:
			if localType.array == nil {
				return coreField{}, fmt.Errorf("local array type %d has no metadata", localType.id)
			}
			if targetType.kind != btfKindArray || targetType.array == nil {
				return coreField{}, fmt.Errorf("%w: target type is not an array", errCoreTargetNotFound)
			}
			if localType.array.nelems != 0 && index >= localType.array.nelems {
				return coreField{}, fmt.Errorf("array index %d is outside local array of %d elements", index, localType.array.nelems)
			}
			if targetType.array.nelems != 0 && index >= targetType.array.nelems {
				return coreField{}, fmt.Errorf("%w: array index %d is outside target array of %d elements", errCoreTargetNotFound, index, targetType.array.nelems)
			}
			elementSize, err := targetBTF.sizeof(targetType.array.typeID)
			if err != nil {
				return coreField{}, err
			}
			offset, err := coreArrayBitOffset(index, elementSize)
			if err != nil {
				return coreField{}, err
			}
			field.bitOffset, err = addCoreBitOffset(field.bitOffset, offset)
			if err != nil {
				return coreField{}, err
			}
			field.typeID = targetType.array.typeID
			field.bitfieldSize = 0
			field.bitfieldOffset = 0
			field.loadSize = 0
			localType = localBTF.resolveType(localType.array.typeID)
			targetType = targetBTF.resolveType(targetType.array.typeID)

		default:
			return coreField{}, fmt.Errorf("cannot descend into local %s %q", btfKindName(localType.kind), localType.name)
		}

		if localType == nil || targetType == nil || !coreFieldsCompatible(localBTF, targetBTF, localType.id, targetType.id, make(map[uint64]bool)) {
			return coreField{}, fmt.Errorf("%w: field types are incompatible", errCoreTargetNotFound)
		}
	}

	if field.bitfieldSize > 0 {
		if err := targetBTF.adjustCoreBitfield(&field); err != nil {
			return coreField{}, err
		}
	}
	return field, nil
}

func coreArrayBitOffset(index, elementSize uint32) (uint32, error) {
	offset := uint64(index) * uint64(elementSize) * 8
	if offset > uint64(^uint32(0)) {
		return 0, errors.New("CO-RE array offset overflows uint32")
	}
	return uint32(offset), nil
}

func addCoreBitOffset(base, offset uint32) (uint32, error) {
	result := uint64(base) + uint64(offset)
	if result > uint64(^uint32(0)) {
		return 0, errors.New("CO-RE field offset overflows uint32")
	}
	return uint32(result), nil
}

func coreFieldsCompatible(localBTF, targetBTF *btfSpec, localID, targetID uint32, visited map[uint64]bool) bool {
	localType := localBTF.resolveType(localID)
	targetType := targetBTF.resolveType(targetID)
	if localType == nil || targetType == nil {
		return localID == 0 && targetID == 0
	}
	key := uint64(localType.id)<<32 | uint64(targetType.id)
	if visited[key] {
		return true
	}
	visited[key] = true

	localComposite := localType.kind == btfKindStruct || localType.kind == btfKindUnion
	targetComposite := targetType.kind == btfKindStruct || targetType.kind == btfKindUnion
	if localComposite || targetComposite {
		return localComposite && targetComposite
	}
	if isCoreEnumKind(localType.kind) || isCoreEnumKind(targetType.kind) {
		return isCoreEnumKind(localType.kind) && isCoreEnumKind(targetType.kind) &&
			coreNamesMatch(localType.name, targetType.name)
	}
	if localType.kind != targetType.kind {
		return false
	}

	switch localType.kind {
	case btfKindPtr, btfKindInt, btfKindFloat:
		return true
	case btfKindArray:
		return localType.array != nil && targetType.array != nil &&
			coreFieldsCompatible(localBTF, targetBTF, localType.array.typeID, targetType.array.typeID, visited)
	case btfKindFwd:
		return coreNamesMatch(localType.name, targetType.name)
	default:
		return false
	}
}

func isCoreEnumKind(kind uint32) bool {
	return kind == btfKindEnum || kind == btfKindEnum64
}

func coreNamesMatch(local, target string) bool {
	return local == "" || target == "" || coreEssentialName(local) == coreEssentialName(target)
}

func validateCoreTypeAccess(access string) error {
	accessors, err := parseCoreAccess(access)
	if err != nil {
		return err
	}
	if len(accessors) != 1 || accessors[0] != 0 {
		return fmt.Errorf("type relocation requires access path 0, got %q", access)
	}
	return nil
}

func resolveCoreTypeReloc(localBTF, targetBTF *btfSpec, typeID uint32, access string, kind uint32) (uint64, error) {
	if err := validateCoreTypeAccess(access); err != nil {
		return 0, err
	}
	localType := localBTF.resolveType(typeID)
	if localType == nil {
		return 0, fmt.Errorf("local BTF type id %d not found", typeID)
	}
	targetType := targetBTF.findCoreTargetType(localType)
	if targetType == nil {
		if kind == bpfCoreTypeExists || kind == bpfCoreTypeMatches {
			return 0, nil
		}
		return 0, fmt.Errorf("%w: target BTF is missing %s %q", errCoreTargetNotFound, btfKindName(localType.kind), localType.name)
	}

	if kind == bpfCoreTypeMatches {
		if coreTypesMatch(localBTF, targetBTF, localType.id, targetType.id, make(map[uint64]bool)) {
			return 1, nil
		}
		return 0, nil
	}
	compatible := coreTypesCompatible(localBTF, targetBTF, localType.id, targetType.id, make(map[uint64]bool))
	if kind == bpfCoreTypeExists {
		if compatible {
			return 1, nil
		}
		return 0, nil
	}
	if !compatible {
		return 0, fmt.Errorf("%w: target %s %q is incompatible", errCoreTargetNotFound, btfKindName(targetType.kind), targetType.name)
	}

	switch kind {
	case bpfCoreTypeIDTarget:
		return uint64(targetType.id), nil
	case bpfCoreTypeSize:
		size, err := targetBTF.sizeof(targetType.id)
		return uint64(size), err
	default:
		return 0, fmt.Errorf("unsupported type CO-RE relocation kind %d", kind)
	}
}

func resolveCoreEnumReloc(localBTF, targetBTF *btfSpec, typeID uint32, access string, kind uint32) (uint64, error) {
	accessors, err := parseCoreAccess(access)
	if err != nil {
		return 0, err
	}
	if len(accessors) != 1 {
		return 0, fmt.Errorf("enum relocation requires one value index, got %q", access)
	}
	localType := localBTF.resolveType(typeID)
	if localType == nil || !isCoreEnumKind(localType.kind) {
		return 0, fmt.Errorf("local BTF type id %d is not an enum", typeID)
	}
	index := accessors[0]
	if index >= uint32(len(localType.enumValues)) {
		return 0, fmt.Errorf("enum value index %d is outside local enum %q", index, localType.name)
	}
	localValue := localType.enumValues[index]
	targetType := targetBTF.findCoreTargetType(localType)
	if targetType == nil || !isCoreEnumKind(targetType.kind) {
		if kind == bpfCoreEnumvalExists {
			return 0, nil
		}
		return 0, fmt.Errorf("%w: target BTF is missing enum %q", errCoreTargetNotFound, localType.name)
	}
	for _, targetValue := range targetType.enumValues {
		if coreEssentialName(targetValue.name) != coreEssentialName(localValue.name) {
			continue
		}
		if kind == bpfCoreEnumvalExists {
			return 1, nil
		}
		if kind == bpfCoreEnumvalValue {
			return targetValue.value, nil
		}
		return 0, fmt.Errorf("unsupported enum CO-RE relocation kind %d", kind)
	}
	if kind == bpfCoreEnumvalExists {
		return 0, nil
	}
	return 0, fmt.Errorf("%w: target enum %q is missing value %q", errCoreTargetNotFound, targetType.name, localValue.name)
}

func coreTypesCompatible(localBTF, targetBTF *btfSpec, localID, targetID uint32, visited map[uint64]bool) bool {
	if localID == 0 || targetID == 0 {
		return localID == targetID
	}
	localType := localBTF.resolveType(localID)
	targetType := targetBTF.resolveType(targetID)
	if localType == nil || targetType == nil {
		return false
	}
	key := uint64(localType.id)<<32 | uint64(targetType.id)
	if visited[key] {
		return true
	}
	visited[key] = true

	if isCoreEnumKind(localType.kind) || isCoreEnumKind(targetType.kind) {
		return isCoreEnumKind(localType.kind) && isCoreEnumKind(targetType.kind)
	}
	if localType.kind != targetType.kind {
		return false
	}
	switch localType.kind {
	case btfKindInt, btfKindStruct, btfKindUnion, btfKindFwd, btfKindFloat:
		return true
	case btfKindPtr, btfKindFunc:
		return coreTypesCompatible(localBTF, targetBTF, localType.typeID, targetType.typeID, visited)
	case btfKindArray:
		return localType.array != nil && targetType.array != nil &&
			coreTypesCompatible(localBTF, targetBTF, localType.array.indexTypeID, targetType.array.indexTypeID, visited) &&
			coreTypesCompatible(localBTF, targetBTF, localType.array.typeID, targetType.array.typeID, visited)
	case btfKindFuncProto:
		if len(localType.params) != len(targetType.params) ||
			!coreTypesCompatible(localBTF, targetBTF, localType.typeID, targetType.typeID, visited) {
			return false
		}
		for i := range localType.params {
			if !coreTypesCompatible(localBTF, targetBTF, localType.params[i], targetType.params[i], visited) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func coreTypesMatch(localBTF, targetBTF *btfSpec, localID, targetID uint32, visited map[uint64]bool) bool {
	if localID == 0 || targetID == 0 {
		return localID == targetID
	}
	localType := localBTF.resolveType(localID)
	targetType := targetBTF.resolveType(targetID)
	if localType == nil || targetType == nil || !coreNamesMatch(localType.name, targetType.name) {
		return false
	}
	key := uint64(localType.id)<<32 | uint64(targetType.id)
	if visited[key] {
		return true
	}
	visited[key] = true

	if isCoreEnumKind(localType.kind) || isCoreEnumKind(targetType.kind) {
		if !isCoreEnumKind(localType.kind) || !isCoreEnumKind(targetType.kind) || localType.size != targetType.size {
			return false
		}
		for _, localValue := range localType.enumValues {
			found := false
			for _, targetValue := range targetType.enumValues {
				if coreNamesMatch(localValue.name, targetValue.name) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	if localType.kind != targetType.kind {
		return false
	}

	switch localType.kind {
	case btfKindInt:
		return localType.size == targetType.size &&
			(localType.intEncoding&btfIntSigned != 0) == (targetType.intEncoding&btfIntSigned != 0)
	case btfKindFloat:
		return localType.size == targetType.size
	case btfKindFwd:
		return localType.kindFlag == targetType.kindFlag
	case btfKindPtr, btfKindFunc:
		return coreTypesMatch(localBTF, targetBTF, localType.typeID, targetType.typeID, visited)
	case btfKindArray:
		return localType.array != nil && targetType.array != nil &&
			localType.array.nelems == targetType.array.nelems &&
			coreTypesMatch(localBTF, targetBTF, localType.array.typeID, targetType.array.typeID, visited)
	case btfKindStruct, btfKindUnion:
		if len(localType.members) > len(targetType.members) {
			return false
		}
		for i, localMember := range localType.members {
			var targetMember *btfMember
			if localMember.name == "" {
				if i < len(targetType.members) {
					targetMember = &targetType.members[i]
				}
			} else {
				targetMember = targetType.member(localMember.name)
			}
			if targetMember == nil || !coreTypesMatch(localBTF, targetBTF, localMember.typeID, targetMember.typeID, visited) {
				return false
			}
		}
		return true
	case btfKindFuncProto:
		if len(localType.params) != len(targetType.params) ||
			!coreTypesMatch(localBTF, targetBTF, localType.typeID, targetType.typeID, visited) {
			return false
		}
		for i := range localType.params {
			if !coreTypesMatch(localBTF, targetBTF, localType.params[i], targetType.params[i], visited) {
				return false
			}
		}
		return true
	default:
		return false
	}
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

func patchCoreFieldReloc(insns []byte, offset uint32, value uint32, order binary.ByteOrder) error {
	return patchCoreReloc(insns, offset, uint64(value), order)
}

func patchCoreReloc(insns []byte, offset uint32, value uint64, order binary.ByteOrder) error {
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
			return fmt.Errorf("CO-RE value %d does not fit BPF instruction offset", value)
		}
		order.PutUint16(insn[2:4], uint16(value))
	case bpfClassALU, bpfClassALU64:
		if insn[0]&bpfSrcX != 0 {
			return fmt.Errorf("CO-RE relocation at offset %#x targets register-source ALU instruction", offset)
		}
		low := uint32(value)
		if value > 0x7fffffff && value != uint64(int64(int32(low))) {
			return fmt.Errorf("CO-RE value %d does not fit signed BPF immediate", value)
		}
		order.PutUint32(insn[4:8], low)
	case bpfClassLD:
		if insn[0] != 0x18 {
			return fmt.Errorf("CO-RE relocation at offset %#x targets a non-64-bit immediate load", offset)
		}
		if uint64(offset)+16 > uint64(len(insns)) {
			return fmt.Errorf("CO-RE 64-bit load at offset %#x is truncated", offset)
		}
		order.PutUint32(insn[4:8], uint32(value))
		order.PutUint32(insns[offset+12:offset+16], uint32(value>>32))
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
		MapFlags:              bpfFLink,
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

func (obj *bpfObject) structOpsValue(ops *structOpsInfo, targetBTF *btfSpec, programs map[string]int) ([]byte, error) {
	value := make([]byte, ops.valueSize)
	if ops.dataOffset > uint32(len(value)) {
		return nil, errors.New("struct_ops data offset exceeds value size")
	}
	if err := obj.copyStructOpsBytes(value, ops, targetBTF, "name"); err != nil {
		return nil, err
	}
	if err := obj.copyStructOpsUint(value, ops, targetBTF, "flags"); err != nil {
		return nil, err
	}

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
		size, err := targetBTF.sizeof(member.typeID)
		if err != nil {
			return nil, fmt.Errorf("size of tcp_congestion_ops.%s: %w", memberName, err)
		}
		if size != 8 {
			return nil, fmt.Errorf("tcp_congestion_ops.%s has pointer size %d, want 8", memberName, size)
		}
		offset := ops.dataOffset + member.offset
		if offset+size > uint32(len(value)) {
			return nil, fmt.Errorf("member %s is outside struct_ops value", memberName)
		}
		order.PutUint64(value[offset:offset+size], uint64(fd))
	}
	return value, nil
}

func (obj *bpfObject) structOpsSourceField(name string) ([]byte, error) {
	typeID, err := obj.btfSpec.varTypeID("brutal")
	if err != nil {
		return nil, err
	}
	typ := obj.btfSpec.resolveType(typeID)
	if typ == nil || typ.kind != btfKindStruct {
		return nil, errors.New("BTF var brutal is not a struct")
	}
	member := typ.member(name)
	if member == nil {
		return nil, fmt.Errorf("object tcp_congestion_ops is missing member %s", name)
	}
	if member.bitOffset%8 != 0 {
		return nil, fmt.Errorf("object tcp_congestion_ops.%s is not byte aligned", name)
	}
	size, err := obj.btfSpec.sizeof(member.typeID)
	if err != nil {
		return nil, fmt.Errorf("size of object tcp_congestion_ops.%s: %w", name, err)
	}
	offset := member.bitOffset / 8
	if offset+size > uint32(len(obj.structOpsData)) {
		return nil, fmt.Errorf("object tcp_congestion_ops.%s is outside struct_ops data", name)
	}
	return obj.structOpsData[offset : offset+size], nil
}

func structOpsTargetField(value []byte, ops *structOpsInfo, targetBTF *btfSpec, name string) ([]byte, error) {
	member, ok := ops.members[name]
	if !ok {
		return nil, fmt.Errorf("kernel tcp_congestion_ops is missing member %s", name)
	}
	size, err := targetBTF.sizeof(member.typeID)
	if err != nil {
		return nil, fmt.Errorf("size of kernel tcp_congestion_ops.%s: %w", name, err)
	}
	offset := ops.dataOffset + member.offset
	if offset+size > uint32(len(value)) {
		return nil, fmt.Errorf("kernel tcp_congestion_ops.%s is outside struct_ops value", name)
	}
	return value[offset : offset+size], nil
}

func (obj *bpfObject) copyStructOpsBytes(value []byte, ops *structOpsInfo, targetBTF *btfSpec, name string) error {
	source, err := obj.structOpsSourceField(name)
	if err != nil {
		return err
	}
	target, err := structOpsTargetField(value, ops, targetBTF, name)
	if err != nil {
		return err
	}
	copy(target, source)
	return nil
}

func (obj *bpfObject) copyStructOpsUint(value []byte, ops *structOpsInfo, targetBTF *btfSpec, name string) error {
	source, err := obj.structOpsSourceField(name)
	if err != nil {
		return err
	}
	n, err := decodeUint(source, obj.order)
	if err != nil {
		return fmt.Errorf("decode object tcp_congestion_ops.%s: %w", name, err)
	}
	target, err := structOpsTargetField(value, ops, targetBTF, name)
	if err != nil {
		return err
	}
	if err := encodeUint(target, n, nativeByteOrder()); err != nil {
		return fmt.Errorf("encode kernel tcp_congestion_ops.%s: %w", name, err)
	}
	return nil
}

func decodeUint(data []byte, order binary.ByteOrder) (uint64, error) {
	switch len(data) {
	case 1:
		return uint64(data[0]), nil
	case 2:
		return uint64(order.Uint16(data)), nil
	case 4:
		return uint64(order.Uint32(data)), nil
	case 8:
		return order.Uint64(data), nil
	default:
		return 0, fmt.Errorf("unsupported integer size %d", len(data))
	}
}

func encodeUint(data []byte, value uint64, order binary.ByteOrder) error {
	if len(data) < 8 {
		bits := uint(len(data) * 8)
		max := uint64(1)<<bits - 1
		if value > max {
			return fmt.Errorf("integer value %d does not fit %d bytes", value, len(data))
		}
	}
	switch len(data) {
	case 1:
		data[0] = byte(value)
	case 2:
		order.PutUint16(data, uint16(value))
	case 4:
		order.PutUint32(data, uint32(value))
	case 8:
		order.PutUint64(data, value)
	default:
		return fmt.Errorf("unsupported integer size %d", len(data))
	}
	return nil
}

func attachSetsockopt(progFD int, cgroupPath string) (int, error) {
	cgroupFD, err := syscall.Open(cgroupPath, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open cgroup %s: %w", cgroupPath, err)
	}
	defer syscall.Close(cgroupFD)

	fd, err := linkCreate(progFD, cgroupFD, bpfAttachSetOpt, 0)
	if err != nil {
		return -1, fmt.Errorf("attach cgroup setsockopt hook: %w", err)
	}
	return fd, nil
}

func unload(opts Options) error {
	// Detach the policy hook first. If that fails, preserve struct_ops so the
	// still-attached hook never points clients at an algorithm we removed.
	if err := unloadSetsockopt(opts); err != nil {
		return fmt.Errorf("remove setsockopt state: %w", err)
	}
	if err := unloadStructOps(); err != nil {
		return fmt.Errorf("remove struct_ops state: %w", err)
	}
	return nil
}

func unloadStructOps() error {
	fd, err := objGet(structOpsPinPath)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open pinned struct_ops object %s: %w", structOpsPinPath, err)
	}
	defer syscall.Close(fd)

	kind, err := bpfObjectKind(fd)
	if err != nil {
		return fmt.Errorf("identify pinned struct_ops object %s: %w", structOpsPinPath, err)
	}
	switch kind {
	case bpfFDLink:
		linkInfo, err := getLinkInfo(fd)
		if err != nil {
			return fmt.Errorf("inspect pinned struct_ops link %s: %w", structOpsPinPath, err)
		}
		if err := validateStructOpsLinkInfo(linkInfo); err != nil {
			return fmt.Errorf("refuse to detach unexpected link at %s: %w", structOpsPinPath, err)
		}
		return unlinkAndDetachLink(fd, structOpsPinPath)

	case bpfFDMap:
		mapInfo, err := getMapInfo(fd)
		if err != nil {
			return fmt.Errorf("inspect legacy struct_ops map %s: %w", structOpsPinPath, err)
		}
		if mapInfo.Type != bpfMapTypeOps || cString(mapInfo.Name[:]) != "brutal" || mapInfo.MapFlags&bpfFLink != 0 {
			return fmt.Errorf("refuse to unregister unexpected map at %s (type %d, name %q, flags %#x)", structOpsPinPath, mapInfo.Type, cString(mapInfo.Name[:]), mapInfo.MapFlags)
		}
		if err := unregisterStructOps(fd); err != nil {
			return fmt.Errorf("unregister legacy struct_ops map %s: %w", structOpsPinPath, err)
		}
		return unlinkIfExists(structOpsPinPath)

	default:
		return fmt.Errorf("pinned object %s is a %s, want a struct_ops link or legacy map", structOpsPinPath, kind)
	}
}

func unlinkAndDetachLink(fd int, path string) error {
	if err := linkDetach(fd); err != nil &&
		!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ENOLINK) {
		return fmt.Errorf("detach BPF link %s: %w", path, err)
	}
	return unlinkIfExists(path)
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
	fd, err := objGet(setsockoptPinPath)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open pinned cgroup setsockopt object %s: %w", setsockoptPinPath, err)
	}
	defer syscall.Close(fd)

	kind, err := bpfObjectKind(fd)
	if err != nil {
		return fmt.Errorf("identify pinned cgroup setsockopt object %s: %w", setsockoptPinPath, err)
	}
	if kind == bpfFDLink {
		linkInfo, err := getLinkInfo(fd)
		if err != nil {
			return fmt.Errorf("inspect pinned cgroup setsockopt link %s: %w", setsockoptPinPath, err)
		}
		if err := validateSetsockoptLinkInfo(linkInfo); err != nil {
			return fmt.Errorf("refuse to detach unexpected link at %s: %w", setsockoptPinPath, err)
		}
		return unlinkAndDetachLink(fd, setsockoptPinPath)
	}
	if kind != bpfFDProgram {
		return fmt.Errorf("pinned object %s is a %s, want a cgroup link or legacy program", setsockoptPinPath, kind)
	}

	progInfo, err := getProgInfo(fd)
	if err != nil {
		return fmt.Errorf("inspect legacy cgroup setsockopt program %s: %w", setsockoptPinPath, err)
	}
	if progInfo.Type != bpfProgCgrpOpt || cString(progInfo.Name[:]) != bpfKernelName("brutal_setsockopt") {
		return fmt.Errorf("pinned object %s is neither a brutal cgroup link nor program", setsockoptPinPath)
	}

	cgroupFD, err := syscall.Open(opts.CgroupPath, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open cgroup %s: %w", opts.CgroupPath, err)
	}
	defer syscall.Close(cgroupFD)

	if err := progDetach(cgroupFD, fd, bpfAttachSetOpt); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("legacy setsockopt program is not attached to cgroup %s; pin was preserved so it can be detached with the original CgroupPath", opts.CgroupPath)
		}
		return fmt.Errorf("detach legacy cgroup setsockopt hook: %w", err)
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

func linkCreate(progOrMapFD, targetFD int, attachType, flags uint32) (int, error) {
	attr := linkCreateAttr{
		ProgOrMapFd: uint32(progOrMapFD),
		TargetFd:    uint32(targetFD),
		AttachType:  attachType,
		Flags:       flags,
	}
	return bpf(bpfLinkCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
}

func linkDetach(fd int) error {
	attr := linkDetachAttr{LinkFd: uint32(fd)}
	_, err := bpf(bpfLinkDetach, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

func getFDInfo(fd int, info unsafe.Pointer, size uintptr) error {
	attr := objInfoAttr{
		BpfFd:   uint32(fd),
		InfoLen: uint32(size),
		Info:    uint64(uintptr(info)),
	}
	_, err := bpf(bpfObjGetInfo, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(info)
	return err
}

func getLinkInfo(fd int) (bpfLinkInfo, error) {
	var info bpfLinkInfo
	err := getFDInfo(fd, unsafe.Pointer(&info), unsafe.Sizeof(info))
	return info, err
}

func getProgInfo(fd int) (bpfProgInfo, error) {
	var info bpfProgInfo
	err := getFDInfo(fd, unsafe.Pointer(&info), unsafe.Sizeof(info))
	return info, err
}

func getMapInfo(fd int) (bpfMapInfo, error) {
	var info bpfMapInfo
	err := getFDInfo(fd, unsafe.Pointer(&info), unsafe.Sizeof(info))
	return info, err
}

func progGetFDByID(id uint32) (int, error) {
	return getFDByID(bpfProgGetFD, id)
}

func mapGetFDByID(id uint32) (int, error) {
	return getFDByID(bpfMapGetFD, id)
}

func getFDByID(command int, id uint32) (int, error) {
	attr := idAttr{ID: id}
	return bpf(command, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
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
	id          uint32
	name        string
	kind        uint32
	size        uint32
	typeID      uint32
	intEncoding uint32
	kindFlag    bool
	array       *btfArray
	members     []btfMember
	enumValues  []btfEnumValue
	paramCount  uint32
	params      []uint32
	varType     uint32
}

type btfMember struct {
	name         string
	typeID       uint32
	bitOffset    uint32
	bitfieldSize uint32
}

type btfArray struct {
	typeID      uint32
	indexTypeID uint32
	nelems      uint32
}

type btfEnumValue struct {
	name  string
	value uint64
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
		kindFlag := info&btfKindFlag != 0
		vlen := info & 0xffff
		t := &btfType{
			id:       id,
			name:     spec.string(nameOff),
			kind:     kind,
			size:     sizeType,
			typeID:   sizeType,
			kindFlag: kindFlag,
		}

		switch kind {
		case btfKindInt:
			if off+4 > uint32(len(types)) {
				return nil, fmt.Errorf("truncated BTF int info for %s", t.name)
			}
			t.intEncoding = (order.Uint32(types[off:off+4]) >> 24) & 0x0f
			off += 4
		case btfKindPtr, btfKindFwd, btfKindTypedef, btfKindVolatile, btfKindConst, btfKindRestrict, btfKindFunc, btfKindFloat, btfKindTypeTag:
		case btfKindArray:
			if off+12 > uint32(len(types)) {
				return nil, fmt.Errorf("truncated BTF array info for %s", t.name)
			}
			t.array = &btfArray{
				typeID:      order.Uint32(types[off : off+4]),
				indexTypeID: order.Uint32(types[off+4 : off+8]),
				nelems:      order.Uint32(types[off+8 : off+12]),
			}
			off += 12
		case btfKindStruct, btfKindUnion:
			t.members = make([]btfMember, 0, vlen)
			for i := uint32(0); i < vlen; i++ {
				if off+12 > uint32(len(types)) {
					return nil, fmt.Errorf("truncated BTF members for %s", t.name)
				}
				rawOffset := order.Uint32(types[off+8 : off+12])
				bitOffset := rawOffset
				var bitfieldSize uint32
				if kindFlag {
					bitOffset = rawOffset & 0x00ffffff
					bitfieldSize = rawOffset >> 24
				}
				t.members = append(t.members, btfMember{
					name:         spec.string(order.Uint32(types[off : off+4])),
					typeID:       order.Uint32(types[off+4 : off+8]),
					bitOffset:    bitOffset,
					bitfieldSize: bitfieldSize,
				})
				off += 12
			}
		case btfKindEnum:
			t.enumValues = make([]btfEnumValue, 0, vlen)
			for i := uint32(0); i < vlen; i++ {
				if off+8 > uint32(len(types)) {
					return nil, fmt.Errorf("truncated BTF enum values for %s", t.name)
				}
				raw := order.Uint32(types[off+4 : off+8])
				value := uint64(raw)
				if kindFlag {
					value = uint64(int64(int32(raw)))
				}
				t.enumValues = append(t.enumValues, btfEnumValue{
					name:  spec.string(order.Uint32(types[off : off+4])),
					value: value,
				})
				off += 8
			}
		case btfKindFuncProto:
			if off+8*vlen > uint32(len(types)) {
				return nil, fmt.Errorf("truncated BTF function prototype for %s", t.name)
			}
			t.paramCount = vlen
			t.params = make([]uint32, 0, vlen)
			for i := uint32(0); i < vlen; i++ {
				t.params = append(t.params, order.Uint32(types[off+4:off+8]))
				off += 8
			}
		case btfKindVar:
			t.varType = sizeType
			off += 4
		case btfKindDatasec:
			off += 12 * vlen
		case btfKindDeclTag:
			off += 4
		case btfKindEnum64:
			t.enumValues = make([]btfEnumValue, 0, vlen)
			for i := uint32(0); i < vlen; i++ {
				if off+12 > uint32(len(types)) {
					return nil, fmt.Errorf("truncated BTF enum64 values for %s", t.name)
				}
				t.enumValues = append(t.enumValues, btfEnumValue{
					name: spec.string(order.Uint32(types[off : off+4])),
					value: uint64(order.Uint32(types[off+4:off+8])) |
						uint64(order.Uint32(types[off+8:off+12]))<<32,
				})
				off += 12
			}
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

func (s *btfSpec) findCoreTargetType(local *btfType) *btfType {
	if local == nil {
		return nil
	}
	name := coreEssentialName(local.name)
	for _, typ := range s.types {
		kindMatches := typ.kind == local.kind || isCoreEnumKind(typ.kind) && isCoreEnumKind(local.kind)
		if kindMatches && coreEssentialName(typ.name) == name {
			return typ
		}
	}
	return nil
}

func (s *btfSpec) findCoreMember(root *btfType, name string) (btfMember, error) {
	if name == "" {
		return btfMember{}, errors.New("cannot search for an anonymous CO-RE member")
	}
	type candidate struct {
		typ       *btfType
		bitOffset uint32
	}
	queue := []candidate{{typ: root}}
	visited := make(map[uint32]bool)
	for len(queue) != 0 {
		current := queue[0]
		queue = queue[1:]
		current.typ = s.resolveType(current.typ.id)
		if current.typ == nil || (current.typ.kind != btfKindStruct && current.typ.kind != btfKindUnion) {
			continue
		}
		if visited[current.typ.id] {
			continue
		}
		visited[current.typ.id] = true
		if len(visited) > 64 {
			return btfMember{}, errors.New("CO-RE anonymous member nesting exceeds 64 types")
		}
		for _, member := range current.typ.members {
			offset, err := addCoreBitOffset(current.bitOffset, member.bitOffset)
			if err != nil {
				return btfMember{}, err
			}
			if member.name == name {
				member.bitOffset = offset
				return member, nil
			}
			if member.name != "" {
				continue
			}
			child := s.resolveType(member.typeID)
			if child != nil && (child.kind == btfKindStruct || child.kind == btfKindUnion) {
				queue = append(queue, candidate{typ: child, bitOffset: offset})
			}
		}
	}
	return btfMember{}, fmt.Errorf("%w: target type %q is missing member %q", errCoreTargetNotFound, root.name, name)
}

func coreEssentialName(name string) string {
	if index := strings.LastIndex(name, "___"); index > 0 {
		return name[:index]
	}
	return name
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
	case btfKindInt, btfKindStruct, btfKindUnion, btfKindEnum, btfKindEnum64, btfKindFloat:
		return typ.size, nil
	case btfKindArray:
		if typ.array == nil {
			return 0, fmt.Errorf("array type %d has no array metadata", typeID)
		}
		elementSize, err := s.sizeof(typ.array.typeID)
		if err != nil {
			return 0, err
		}
		size := uint64(elementSize) * uint64(typ.array.nelems)
		if size > uint64(^uint32(0)) {
			return 0, fmt.Errorf("array type %d size overflows uint32", typeID)
		}
		return uint32(size), nil
	case btfKindPtr:
		return 8, nil
	case btfKindTypedef, btfKindVolatile, btfKindConst, btfKindRestrict, btfKindTypeTag:
		return s.sizeof(typ.typeID)
	default:
		return 0, fmt.Errorf("unsupported sizeof kind %d for %s", typ.kind, typ.name)
	}
}

func (s *btfSpec) adjustCoreBitfield(field *coreField) error {
	offset, loadSize, err := s.coreBitfieldLayout(*field)
	if err != nil {
		return err
	}
	field.bitfieldOffset = field.bitOffset - offset*8
	field.loadSize = loadSize
	return nil
}

func (s *btfSpec) coreBitfieldByteOffset(field coreField) (uint32, error) {
	offset, _, err := s.coreBitfieldLayout(field)
	return offset, err
}

func (s *btfSpec) coreBitfieldLayout(field coreField) (uint32, uint32, error) {
	loadSize, err := s.sizeof(field.typeID)
	if err != nil {
		return 0, 0, err
	}
	if loadSize == 0 {
		return 0, 0, errors.New("zero-sized bitfield container")
	}
	if loadSize&(loadSize-1) != 0 {
		normalized := uint32(1)
		for normalized < loadSize {
			if normalized == 8 {
				return 0, 0, fmt.Errorf("bitfield container size %d exceeds BPF load width", loadSize)
			}
			normalized <<= 1
		}
		loadSize = normalized
	}
	if loadSize > 8 {
		return 0, 0, fmt.Errorf("bitfield container size %d exceeds BPF load width", loadSize)
	}

	end := uint64(field.bitOffset) + uint64(field.bitfieldSize)
	for {
		offset := field.bitOffset / 8 / loadSize * loadSize
		if end <= (uint64(offset)+uint64(loadSize))*8 {
			return offset, loadSize, nil
		}
		if loadSize == 8 {
			return 0, 0, fmt.Errorf("bitfield at bit %d with size %d cannot be loaded atomically", field.bitOffset, field.bitfieldSize)
		}
		loadSize <<= 1
	}
}

func (s *btfSpec) coreFieldBitSize(field coreField) (uint32, error) {
	if field.bitfieldSize > 0 {
		return field.bitfieldSize, nil
	}
	size, err := s.sizeof(field.typeID)
	if err != nil {
		return 0, err
	}
	return size * 8, nil
}

func (s *btfSpec) coreFieldSigned(typeID uint32) (uint32, error) {
	typ := s.resolveType(typeID)
	if typ == nil {
		return 0, fmt.Errorf("invalid type id %d", typeID)
	}
	if typ.kind == btfKindEnum || typ.kind == btfKindEnum64 {
		if typ.kindFlag {
			return 1, nil
		}
		return 0, nil
	}
	if typ.kind != btfKindInt {
		return 0, fmt.Errorf("type %q has no integer signedness", typ.name)
	}
	if typ.intEncoding&btfIntSigned != 0 {
		return 1, nil
	}
	return 0, nil
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
	if data.bitOffset%8 != 0 {
		return nil, fmt.Errorf("kernel BTF struct %s data member is not byte aligned", wrapperName)
	}
	dataType := s.resolveType(data.typeID)
	if dataType == nil || dataType.kind != btfKindStruct || dataType.id != inner.id {
		return nil, fmt.Errorf("kernel BTF struct %s data member is not struct %s", wrapperName, innerName)
	}
	if data.bitOffset/8+inner.size > wrapper.size {
		return nil, fmt.Errorf("kernel BTF struct %s data member exceeds wrapper size", wrapperName)
	}
	info.valueTypeID = wrapper.id
	info.valueSize = wrapper.size
	info.dataOffset = data.bitOffset / 8

	for i, member := range inner.members {
		if member.bitOffset%8 != 0 || member.bitfieldSize != 0 {
			return nil, fmt.Errorf("kernel tcp_congestion_ops.%s is not a byte-aligned regular field", member.name)
		}
		info.members[member.name] = structOpsMember{
			index:  uint32(i),
			offset: member.bitOffset / 8,
			typeID: member.typeID,
		}
	}
	return info, nil
}

func (s *btfSpec) tcpCongControlParamCount(ops *structOpsInfo) (int, error) {
	member, ok := ops.members["cong_control"]
	if !ok {
		return 0, errors.New("kernel tcp_congestion_ops is missing member cong_control")
	}
	proto := s.funcProto(member.typeID)
	if proto == nil {
		return 0, errors.New("kernel tcp_congestion_ops.cong_control is not a function pointer")
	}
	return int(proto.paramCount), nil
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
	for depth := 0; depth < 64; depth++ {
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
	return nil
}

func (t *btfType) member(name string) *btfMember {
	for i := range t.members {
		if t.members[i].name == name {
			return &t.members[i]
		}
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
