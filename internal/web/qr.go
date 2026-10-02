package web

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

var ErrQRTooLong = errors.New("qr payload too long")

type qrVersion struct {
	ec     int
	g1, n1 int
	g2, n2 int
	align  []int
}

var qrTable = []qrVersion{
	{},
	{10, 1, 16, 0, 0, nil},
	{16, 1, 28, 0, 0, []int{6, 18}},
	{26, 1, 44, 0, 0, []int{6, 22}},
	{18, 2, 32, 0, 0, []int{6, 26}},
	{24, 2, 43, 0, 0, []int{6, 30}},
	{16, 4, 27, 0, 0, []int{6, 34}},
	{18, 4, 31, 0, 0, []int{6, 22, 38}},
	{22, 2, 38, 2, 39, []int{6, 24, 42}},
	{22, 3, 36, 2, 37, []int{6, 26, 46}},
	{26, 4, 43, 1, 44, []int{6, 28, 50}},
	{30, 1, 50, 4, 51, []int{6, 30, 54}},
	{22, 6, 36, 2, 37, []int{6, 32, 58}},
	{22, 8, 37, 1, 38, []int{6, 34, 62}},
	{24, 4, 40, 5, 41, []int{6, 26, 46, 66}},
	{24, 5, 41, 5, 42, []int{6, 26, 48, 70}},
}

func (v qrVersion) dataLen() int { return v.g1*v.n1 + v.g2*v.n2 }

type QR struct {
	Size    int
	Version int
	Mask    int
	mod     [][]bool
	fn      [][]bool
}

func (q *QR) Dark(x, y int) bool { return q.mod[y][x] }

func gfMul(x, y int) int {
	z := 0
	for i := 7; i >= 0; i-- {
		z = (z << 1) ^ ((z >> 7) * 0x11d)
		z ^= ((y >> i) & 1) * x
	}
	return z
}

func rsDivisor(degree int) []int {
	r := make([]int, degree)
	r[degree-1] = 1
	root := 1
	for i := 0; i < degree; i++ {
		for j := 0; j < degree; j++ {
			r[j] = gfMul(r[j], root)
			if j+1 < degree {
				r[j] ^= r[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return r
}

func rsRemainder(data, div []int) []int {
	r := make([]int, len(div))
	for _, b := range data {
		f := b ^ r[0]
		copy(r, r[1:])
		r[len(r)-1] = 0
		for i := range r {
			r[i] ^= gfMul(div[i], f)
		}
	}
	return r
}

type bitbuf []int

func (b *bitbuf) put(v, n int) {
	for i := n - 1; i >= 0; i-- {
		*b = append(*b, (v>>i)&1)
	}
}

func EncodeQR(data []byte, mask int) (*QR, error) {
	ver := 0
	for v := 1; v < len(qrTable); v++ {
		cc := 8
		if v >= 10 {
			cc = 16
		}
		if 4+cc+8*len(data) <= qrTable[v].dataLen()*8 {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, ErrQRTooLong
	}
	t := qrTable[ver]
	var bb bitbuf
	bb.put(4, 4)
	if ver >= 10 {
		bb.put(len(data), 16)
	} else {
		bb.put(len(data), 8)
	}
	for _, c := range data {
		bb.put(int(c), 8)
	}
	capBits := t.dataLen() * 8
	term := capBits - len(bb)
	if term > 4 {
		term = 4
	}
	bb.put(0, term)
	for len(bb)%8 != 0 {
		bb = append(bb, 0)
	}
	for pad := 0xec; len(bb) < capBits; pad ^= 0xec ^ 0x11 {
		bb.put(pad, 8)
	}
	cw := make([]int, len(bb)/8)
	for i := range bb {
		cw[i>>3] |= bb[i] << (7 - uint(i&7))
	}
	div := rsDivisor(t.ec)
	var blocks, ecs [][]int
	off := 0
	for i := 0; i < t.g1+t.g2; i++ {
		n := t.n1
		if i >= t.g1 {
			n = t.n2
		}
		blk := cw[off : off+n]
		off += n
		blocks = append(blocks, blk)
		ecs = append(ecs, rsRemainder(blk, div))
	}
	var final []int
	maxN := t.n1
	if t.n2 > maxN {
		maxN = t.n2
	}
	for i := 0; i < maxN; i++ {
		for _, b := range blocks {
			if i < len(b) {
				final = append(final, b[i])
			}
		}
	}
	for i := 0; i < t.ec; i++ {
		for _, e := range ecs {
			final = append(final, e[i])
		}
	}
	q := newQR(ver)
	q.drawFunctions()
	q.drawCodewords(final)
	if mask < 0 || mask > 7 {
		best := -1
		for m := 0; m < 8; m++ {
			q.applyMask(m)
			q.drawFormat(m)
			p := q.penalty()
			if best < 0 || p < best {
				best = p
				mask = m
			}
			q.applyMask(m)
		}
	}
	q.applyMask(mask)
	q.drawFormat(mask)
	q.Mask = mask
	return q, nil
}

func newQR(ver int) *QR {
	size := 17 + 4*ver
	q := &QR{Size: size, Version: ver}
	q.mod = make([][]bool, size)
	q.fn = make([][]bool, size)
	for i := range q.mod {
		q.mod[i] = make([]bool, size)
		q.fn[i] = make([]bool, size)
	}
	return q
}

func (q *QR) set(x, y int, dark bool) {
	q.mod[y][x] = dark
	q.fn[y][x] = true
}

func (q *QR) drawFunctions() {
	for i := 0; i < q.Size; i++ {
		q.set(6, i, i%2 == 0)
		q.set(i, 6, i%2 == 0)
	}
	q.finder(3, 3)
	q.finder(q.Size-4, 3)
	q.finder(3, q.Size-4)
	al := qrTable[q.Version].align
	n := len(al)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if (i == 0 && j == 0) || (i == 0 && j == n-1) || (i == n-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					d := max(abs(dx), abs(dy))
					q.set(al[i]+dx, al[j]+dy, d != 1)
				}
			}
		}
	}
	q.drawFormat(0)
	if q.Version >= 7 {
		rem := q.Version
		for i := 0; i < 12; i++ {
			rem = (rem << 1) ^ ((rem >> 11) * 0x1f25)
		}
		bits := q.Version<<12 | rem
		for i := 0; i < 18; i++ {
			bit := (bits>>i)&1 != 0
			a := q.Size - 11 + i%3
			b := i / 3
			q.set(a, b, bit)
			q.set(b, a, bit)
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func (q *QR) finder(x, y int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			d := max(abs(dx), abs(dy))
			xx, yy := x+dx, y+dy
			if xx >= 0 && xx < q.Size && yy >= 0 && yy < q.Size {
				q.set(xx, yy, d != 2 && d != 4)
			}
		}
	}
}

func formatBits(mask int) int {
	data := mask
	rem := data
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	return (data<<10 | rem) ^ 0x5412
}

func (q *QR) drawFormat(mask int) {
	bits := formatBits(mask)
	bit := func(i int) bool { return (bits>>i)&1 != 0 }
	for i := 0; i <= 5; i++ {
		q.set(8, i, bit(i))
	}
	q.set(8, 7, bit(6))
	q.set(8, 8, bit(7))
	q.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		q.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		q.set(q.Size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		q.set(8, q.Size-15+i, bit(i))
	}
	q.set(8, q.Size-8, true)
}

func (q *QR) drawCodewords(data []int) {
	i := 0
	for right := q.Size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < q.Size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				up := (right+1)&2 == 0
				y := vert
				if up {
					y = q.Size - 1 - vert
				}
				if !q.fn[y][x] && i < len(data)*8 {
					q.mod[y][x] = (data[i>>3]>>(7-uint(i&7)))&1 != 0
					i++
				}
			}
		}
	}
}

func maskBit(m, x, y int) bool {
	switch m {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	default:
		return ((x+y)%2+x*y%3)%2 == 0
	}
}

func (q *QR) applyMask(m int) {
	for y := 0; y < q.Size; y++ {
		for x := 0; x < q.Size; x++ {
			if !q.fn[y][x] && maskBit(m, x, y) {
				q.mod[y][x] = !q.mod[y][x]
			}
		}
	}
}

func (q *QR) penalty() int {
	p := 0
	n := q.Size
	line := func(get func(i int) bool) {
		run := 1
		for i := 1; i < n; i++ {
			if get(i) == get(i-1) {
				run++
				continue
			}
			if run >= 5 {
				p += run - 2
			}
			run = 1
		}
		if run >= 5 {
			p += run - 2
		}
		for i := 0; i+10 < n; i++ {
			a := get(i) && !get(i+1) && get(i+2) && get(i+3) && get(i+4) && !get(i+5) && get(i+6)
			if a {
				before := !get(i+7) && !get(i+8) && !get(i+9) && !get(i+10)
				if before {
					p += 40
				}
			}
			b := !get(i) && !get(i+1) && !get(i+2) && !get(i+3) && get(i+4) && !get(i+5) && get(i+6) && get(i+7) && get(i+8) && !get(i+9) && get(i+10)
			if b {
				p += 40
			}
		}
	}
	for y := 0; y < n; y++ {
		line(func(i int) bool { return q.mod[y][i] })
	}
	for x := 0; x < n; x++ {
		line(func(i int) bool { return q.mod[i][x] })
	}
	dark := 0
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			c := q.mod[y][x]
			if c {
				dark++
			}
			if x+1 < n && y+1 < n && c == q.mod[y][x+1] && c == q.mod[y+1][x] && c == q.mod[y+1][x+1] {
				p += 3
			}
		}
	}
	total := n * n
	k := (abs(dark*20-total*10) + total - 1) / total
	return p + max(k-1, 0)*10
}

func (q *QR) SVG() string {
	const quiet = 4
	full := q.Size + 2*quiet
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 `)
	b.WriteString(strconv.Itoa(full) + " " + strconv.Itoa(full))
	b.WriteString(`" shape-rendering="crispEdges"><rect width="` + strconv.Itoa(full) + `" height="` + strconv.Itoa(full) + `" fill="#ffffff"/><path fill="#0b0b0c" d="`)
	for y := 0; y < q.Size; y++ {
		for x := 0; x < q.Size; x++ {
			if q.mod[y][x] {
				b.WriteString("M" + strconv.Itoa(x+quiet) + " " + strconv.Itoa(y+quiet) + "h1v1h-1z")
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}

func QRDataURI(text string) (string, error) {
	q, err := EncodeQR([]byte(text), -1)
	if err != nil {
		return "", err
	}
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(q.SVG())), nil
}
