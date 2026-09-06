//go:build windows

package discover

import (
	"encoding/binary"
	"net"
	"unsafe"
)

var getIPNetTable = ipHelper.NewProc("GetIpNetTable")

// MIB_IPNETROW has six DWORDs (the physical address occupies eight bytes).
// Read the native table directly so locale and command output cannot change parsing.
func Neighbors() []Neighbor {
	if err := getIPNetTable.Find(); err != nil {
		return nil
	}
	var size uint32
	status, _, _ := getIPNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if status != 122 {
		return nil
	} // ERROR_INSUFFICIENT_BUFFER
	for range 3 {
		if size < 4 || size > 16<<20 {
			return nil
		}
		buffer := make([]byte, size)
		status, _, _ = getIPNetTable.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0)
		if status == 122 {
			continue
		}
		if status != 0 {
			return nil
		}
		count := int(binary.LittleEndian.Uint32(buffer[:4]))
		if count > (len(buffer)-4)/24 {
			return nil
		}
		var found []Neighbor
		for i := 0; i < count; i++ {
			row := buffer[4+i*24 : 4+(i+1)*24]
			kind := binary.LittleEndian.Uint32(row[20:24])
			if binary.LittleEndian.Uint32(row[4:8]) != 6 || (kind != 3 && kind != 4) {
				continue
			}
			mac := NormaliseMAC(net.HardwareAddr(row[8:14]).String())
			if mac != "" {
				found = append(found, Neighbor{IP: net.IPv4(row[16], row[17], row[18], row[19]), MAC: mac})
			}
		}
		return found
	}
	return nil
}
