//go:build windows

package winutil

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Icon renders the VPNer logo (rounded square with a "V") as an .ico file.
// state colours: on = blue, off = grey, warn = amber.
func Icon(state string) []byte {
	const n = 32
	bg := color.RGBA{0x2f, 0x6f, 0xed, 0xff}
	switch state {
	case "off":
		bg = color.RGBA{0x8b, 0x94, 0x9e, 0xff}
	case "warn":
		bg = color.RGBA{0xd2, 0x99, 0x22, 0xff}
	}
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	r := 7.0
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5
			// rounded rect coverage
			dx := math.Max(math.Max(r-fx, fx-(n-r)), 0)
			dy := math.Max(math.Max(r-fy, fy-(n-r)), 0)
			d := math.Hypot(dx, dy)
			a := math.Min(math.Max(r-d+0.5, 0), 1)
			if a <= 0 {
				continue
			}
			c := bg
			if onV(fx, fy) {
				c = color.RGBA{0xff, 0xff, 0xff, 0xff}
			}
			c.A = uint8(float64(c.A) * a)
			c.R = uint8(float64(c.R) * a)
			c.G = uint8(float64(c.G) * a)
			c.B = uint8(float64(c.B) * a)
			img.SetRGBA(x, y, c)
		}
	}
	var pb bytes.Buffer
	png.Encode(&pb, img)
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, []uint16{0, 1, 1})
	out.Write([]byte{n, n, 0, 0})
	binary.Write(&out, binary.LittleEndian, []uint16{1, 32})
	binary.Write(&out, binary.LittleEndian, []uint32{uint32(pb.Len()), 22})
	out.Write(pb.Bytes())
	return out.Bytes()
}

// onV reports whether a point lies on the "V" stroke (9,10)-(16,23)-(23,10).
func onV(x, y float64) bool {
	seg := func(ax, ay, bx, by float64) float64 {
		vx, vy := bx-ax, by-ay
		t := ((x-ax)*vx + (y-ay)*vy) / (vx*vx + vy*vy)
		t = math.Max(0, math.Min(1, t))
		return math.Hypot(x-(ax+t*vx), y-(ay+t*vy))
	}
	return math.Min(seg(9, 10, 16, 23), seg(16, 23, 23, 10)) <= 1.7
}
