// Command genres writes the app's Windows resources (icon and manifest) as COFF
// objects the Go linker picks up automatically, and the icon as a PNG for Linux. It's standard library only, so
// neither building the app nor regenerating its resources runs third-party code.
//
//	go run ./dev/genres
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
)

const manifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
  <assemblyIdentity type="win32" name="CantSendPackets" version="0.1.0.0" processorArchitecture="*"/>
  <description>CantSendPackets network diagnostics</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <asmv3:application>
    <asmv3:windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">permonitorv2,permonitor</dpiAwareness>
    </asmv3:windowsSettings>
  </asmv3:application>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
`

const (
	rtIcon      = 3
	rtGroupIcon = 14
	rtManifest  = 24

	// groupIconID is the ID Wails looks up for the window icon (winc.AppIconID).
	groupIconID = 3
	manifestID  = 1 // the ID Windows reads a process manifest from
	langEnUS    = 0x0409

	machineAMD64 = 0x8664
	machineARM64 = 0xaa64
	relAddr32NB  = 3 // IMAGE_REL_AMD64_ADDR32NB
	relARMAddr   = 2 // IMAGE_REL_ARM64_ADDR32NB
)

// ------------------------------------------------------------------- the icon

var (
	surface = color.RGBA{0x1a, 0x1b, 0x1d, 0xff}
	blue    = color.RGBA{0x39, 0x87, 0xe5, 0xff}
	red     = color.RGBA{0xe0, 0x4a, 0x4a, 0xff}
)

// shade is the icon's artwork, in 0..1 coordinates: two nodes and a broken link.
// Being resolution independent, it stays crisp at every icon size.
func shade(x, y float64) color.RGBA {
	const r = 0.2
	dx := math.Max(math.Abs(x-.5)-(.5-r), 0)
	dy := math.Max(math.Abs(y-.5)-(.5-r), 0)
	if math.Hypot(dx, dy) > r {
		return color.RGBA{}
	}
	seg := func(x1, y1, x2, y2 float64) float64 {
		vx, vy := x2-x1, y2-y1
		t := math.Max(0, math.Min(1, ((x-x1)*vx+(y-y1)*vy)/(vx*vx+vy*vy)))
		return math.Hypot(x-(x1+t*vx), y-(y1+t*vy))
	}
	switch {
	case seg(.44, .34, .56, .66) < .04:
		return red
	case math.Hypot(x-.2, y-.5) < .1, math.Hypot(x-.8, y-.5) < .1:
		return blue
	case seg(.2, .5, .38, .5) < .035, seg(.62, .5, .8, .5) < .035:
		return blue
	}
	return surface
}

func render(size int) *image.NRGBA {
	const ss = 4 // supersampling
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					c := shade((float64(px)+(float64(sx)+.5)/ss)/float64(size), (float64(py)+(float64(sy)+.5)/ss)/float64(size))
					al := float64(c.A) / 255
					r, g, b, a = r+float64(c.R)*al, g+float64(c.G)*al, b+float64(c.B)*al, a+al
				}
			}
			if a > 0 {
				img.SetNRGBA(px, py, color.NRGBA{uint8(r / a), uint8(g / a), uint8(b / a), uint8(255 * a / (ss * ss))})
			}
		}
	}
	return img
}

// encodeDIB produces the classic icon image format: a 32-bit bottom-up bitmap
// whose declared height is doubled to cover the AND mask that follows it.
func encodeDIB(img *image.NRGBA) []byte {
	size := img.Bounds().Dx()
	var b bytes.Buffer
	w := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
	w(uint32(40))      // biSize
	w(int32(size))     // biWidth
	w(int32(size * 2)) // biHeight
	w(uint16(1))       // biPlanes
	w(uint16(32))      // biBitCount
	w([6]uint32{})     // compression through biClrImportant: all zero
	for y := size - 1; y >= 0; y-- {
		for x := 0; x < size; x++ {
			c := img.NRGBAAt(x, y)
			b.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	// The AND mask is unused with an alpha channel, but must be present. Rows are
	// padded to 32 bits.
	b.Write(make([]byte, ((size+31)/32)*4*size))
	return b.Bytes()
}

// icons returns RT_ICON payloads and the RT_GROUP_ICON that indexes them. Small
// sizes are bitmaps for compatibility; 256px is PNG, the format meant for it.
func icons() (images [][]byte, group []byte) {
	sizes := []int{16, 20, 24, 32, 40, 48, 64, 256}
	var g bytes.Buffer
	binary.Write(&g, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))})
	for i, size := range sizes {
		img := render(size)
		var data []byte
		if size == 256 {
			var p bytes.Buffer
			if err := png.Encode(&p, img); err != nil {
				log.Fatal(err)
			}
			data = p.Bytes()
		} else {
			data = encodeDIB(img)
		}
		images = append(images, data)
		dim := byte(size) // 256 is stored as 0
		g.Write([]byte{dim, dim, 0, 0})
		binary.Write(&g, binary.LittleEndian, uint16(1))
		binary.Write(&g, binary.LittleEndian, uint16(32))
		binary.Write(&g, binary.LittleEndian, uint32(len(data)))
		binary.Write(&g, binary.LittleEndian, uint16(i+1))
	}
	return images, g.Bytes()
}

// ------------------------------------------------------------------ the object

type resource struct {
	typeID, id uint16
	data       []byte
}

func align(n, to int) int { return (n + to - 1) / to * to }

// buildSection lays out the three-level resource directory (type, id, language)
// followed by the data. It returns the offsets of the data entries' RVA fields,
// which the linker must relocate.
func buildSection(res []resource) (section []byte, relocs []uint32) {
	var types []uint16
	byType := map[uint16][]resource{}
	for _, r := range res { // input is already ordered by type and ID, as the format requires
		if len(byType[r.typeID]) == 0 {
			types = append(types, r.typeID)
		}
		byType[r.typeID] = append(byType[r.typeID], r)
	}

	const dirLen, entryLen, dataEntryLen = 16, 8, 16
	const isDir = 0x80000000

	// First pass: where everything will go.
	rootLen := dirLen + entryLen*len(types)
	offset := rootLen
	typeDirOff := map[uint16]int{}
	for _, t := range types {
		typeDirOff[t] = offset
		offset += dirLen + entryLen*len(byType[t])
	}
	langDirOff := map[[2]uint16]int{}
	for _, t := range types {
		for _, r := range byType[t] {
			langDirOff[[2]uint16{t, r.id}] = offset
			offset += dirLen + entryLen
		}
	}
	dataEntryOff := map[[2]uint16]int{}
	for _, t := range types {
		for _, r := range byType[t] {
			dataEntryOff[[2]uint16{t, r.id}] = offset
			offset += dataEntryLen
		}
	}
	dataOff := map[[2]uint16]int{}
	for _, t := range types {
		for _, r := range byType[t] {
			offset = align(offset, 8)
			dataOff[[2]uint16{t, r.id}] = offset
			offset += len(r.data)
		}
	}

	// Second pass: write it.
	out := make([]byte, align(offset, 8))
	put := binary.LittleEndian.PutUint32
	writeDir := func(at, idEntries int) {
		binary.LittleEndian.PutUint16(out[at+14:], uint16(idEntries))
	}
	writeDir(0, len(types))
	for i, t := range types {
		e := dirLen + i*entryLen
		put(out[e:], uint32(t))
		put(out[e+4:], isDir|uint32(typeDirOff[t]))

		at := typeDirOff[t]
		writeDir(at, len(byType[t]))
		for j, r := range byType[t] {
			key := [2]uint16{t, r.id}
			e := at + dirLen + j*entryLen
			put(out[e:], uint32(r.id))
			put(out[e+4:], isDir|uint32(langDirOff[key]))

			ld := langDirOff[key]
			writeDir(ld, 1)
			put(out[ld+dirLen:], langEnUS)
			put(out[ld+dirLen+4:], uint32(dataEntryOff[key]))

			de := dataEntryOff[key]
			put(out[de:], uint32(dataOff[key])) // relocated into an RVA at link time
			put(out[de+4:], uint32(len(r.data)))
			relocs = append(relocs, uint32(de))
			copy(out[dataOff[key]:], r.data)
		}
	}
	return out, relocs
}

// writeCOFF wraps the section in an object file: header, one section, its
// relocations, and the one section symbol they refer to.
func writeCOFF(path string, machine, relType uint16, section []byte, relocs []uint32) {
	const headerLen, sectionHeaderLen, relocLen = 20, 40, 10
	dataAt := headerLen + sectionHeaderLen
	relocAt := dataAt + len(section)
	symAt := relocAt + relocLen*len(relocs)

	var b bytes.Buffer
	w := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
	w(machine)
	w(uint16(1))     // sections
	w(uint32(0))     // timestamp: zero keeps the output reproducible
	w(uint32(symAt)) // symbol table
	w(uint32(1))     // symbols
	w(uint16(0))     // optional header size
	w(uint16(0))     // characteristics

	name := [8]byte{'.', 'r', 's', 'r', 'c'}
	w(name)
	w(uint32(0)) // virtual size
	w(uint32(0)) // virtual address
	w(uint32(len(section)))
	w(uint32(dataAt))
	w(uint32(relocAt))
	w(uint32(0)) // line numbers
	w(uint16(len(relocs)))
	w(uint16(0))
	w(uint32(0x40000040)) // initialised data, readable

	b.Write(section)
	for _, at := range relocs {
		w(at)
		w(uint32(0)) // symbol index
		w(relType)
	}

	w(name)
	w(uint32(0)) // value
	w(int16(1))  // section number
	w(uint16(0)) // type
	w(uint8(3))  // storage class: static
	w(uint8(0))  // aux symbols

	w(uint32(4)) // empty string table: just its own length

	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
}

func main() {
	images, group := icons()
	var res []resource
	for i, data := range images {
		res = append(res, resource{rtIcon, uint16(i + 1), data})
	}
	res = append(res, resource{rtGroupIcon, groupIconID, group})
	res = append(res, resource{rtManifest, manifestID, []byte(manifest)})

	section, relocs := buildSection(res)
	writeCOFF("rsrc_windows_amd64.syso", machineAMD64, relAddr32NB, section, relocs)
	writeCOFF("rsrc_windows_arm64.syso", machineARM64, relARMAddr, section, relocs)

	// GTK takes the window icon as a PNG; 256 px also serves a .desktop entry.
	var p bytes.Buffer
	if err := png.Encode(&p, render(256)); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("appicon.png", p.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
}
