package vmnet

import (
	"os"
	"syscall"
)

func socketPair(devBufSize, netBufSize int) (*os.File, *os.File, error) {
	pairs, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, nil, err
	}

	if err := setSocketBuffers(pairs[0], devBufSize); err != nil {
		return nil, nil, err
	}
	if err := setSocketBuffers(pairs[1], netBufSize); err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(pairs[0]), ""), os.NewFile(uintptr(pairs[1]), ""), nil
}

func setSocketBuffers(fd int, bufSize int) error {
	// Note that the system expects the value of SO_RCVBUF to be at least double
	// the value of SO_SNDBUF, and for optimal performance, the recommended value
	// of SO_RCVBUF is four times the value of SO_SNDBUF.
	//
	// See: https://developer.apple.com/documentation/virtualization/vzfilehandlenetworkdeviceattachment/3969266-maximumtransmissionunit?language=objc
	err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, bufSize)
	if err != nil {
		return err
	}
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*bufSize)
}
