package tcpraw

import (
	"fmt"
	"net"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func applyBPF(conn *net.IPConn, dstPort int) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return fmt.Errorf("SyscallConn: %w", err)
	}

	instrs := []bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},              // Load first byte of IPv4 header
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x0F}, // Mask IHL
		bpf.ALUOpConstant{Op: bpf.ALUOpMul, Val: 4},    // IHL * 4 (bytes)
		bpf.TAX{},                         // Move result to X register
		bpf.LoadIndirect{Off: 2, Size: 2}, // Load TCP dest port at offset X+2
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(dstPort), SkipFalse: 1},
		bpf.RetConstant{Val: 0xFFFF}, // Accept
		bpf.RetConstant{Val: 0},      // Reject
	}

	rawProg, err := bpf.Assemble(instrs)
	if err != nil {
		conn.Close()
		return fmt.Errorf("bpf.Assemble: %w", err)
	}

	// 3) Convert to unix.SockFilter array
	filters := make([]unix.SockFilter, len(rawProg))
	for i, ins := range rawProg {
		filters[i] = unix.SockFilter{
			Code: ins.Op,
			Jt:   ins.Jt,
			Jf:   ins.Jf,
			K:    ins.K,
		}
	}
	prog := unix.SockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}

	// 4) Attach the filter
	var serr error
	if err := rawConn.Control(func(fd uintptr) {
		serr = unix.SetsockoptSockFprog(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_ATTACH_FILTER,
			&prog,
		)
	}); err != nil {
		conn.Close()
		return fmt.Errorf("rawConn.Control: %w", err)
	}
	if serr != nil {
		conn.Close()
		return fmt.Errorf("SetsockoptSockFprog: %w", serr)
	}

	//	log.Printf("TCP dst port %d with BPF filter attached\n", dstPort)
	return nil
}
