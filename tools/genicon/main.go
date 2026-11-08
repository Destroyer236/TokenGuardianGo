// genicon 生成 Authenticator 的应用图标。
//
// 设计：M3E 风格 —— 深蓝渐变圆角方贴片上叠白色圆角盾牌，
// 盾牌中央镂空钥匙孔（守护 + 密码隐喻）。4x 超采样抗锯齿。
//
// 输出:
//
//	build/appicon.png        1024x1024（Wails 源图标）
//	build/windows/icon.ico   多尺寸 ICO（256/128/64/48/32/16）
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"runtime"
)

const (
	size     = 1024  // 逻辑画布
	supersam = 4     // 超采样倍数
	tileRad  = 232.0 // 贴片圆角
)

var icoSizes = []int{256, 128, 64, 48, 32, 16}

// outputPath 相对源码目录解析输出路径（go run 的 CWD 不固定）。
func outputPath(rel string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), rel)
}

var (
	outPng = outputPath("../../build/appicon.png")
	outIco = outputPath("../../build/windows/icon.ico")
)

// ---- 调色板（与前端 M3E 色板同源） ----
var (
	tileTop    = [3]float64{0x4C, 0x5F, 0xD5} // 种子色
	tileBottom = [3]float64{0x24, 0x33, 0x7F}
	shieldTop  = [3]float64{255, 255, 255}
	shieldBot  = [3]float64{0xD7, 0xDB, 0xF3} // primaryContainer
	shadowCol  = [4]float64{8, 10, 35, 0.16}  // 盾牌投影
)

type pt struct{ x, y float64 }

func lerp(a, b, t float64) float64 { return a + (b-a)*t }

func grad(top, bot [3]float64, y float64) [3]float64 {
	t := math.Min(1, math.Max(0, y/size))
	return [3]float64{lerp(top[0], bot[0], t), lerp(top[1], bot[1], t), lerp(top[2], bot[2], t)}
}

// shieldPath 展平盾牌轮廓。
func shieldPath() []pt {
	poly := []pt{{242, 286}}
	// 顶角圆角
	const n = 24
	for i := 1; i <= n; i++ { // 左上角 Q(242,222)->(306,222)
		t := float64(i) / n
		poly = append(poly, pt{
			(1-t)*(1-t)*242 + 2*(1-t)*t*242 + t*t*306,
			(1-t)*(1-t)*286 + 2*(1-t)*t*222 + t*t*222,
		})
	}
	poly = append(poly, pt{718, 222})
	for i := 1; i <= n; i++ { // 右上角 Q(782,222)->(782,286)
		t := float64(i) / n
		poly = append(poly, pt{
			(1-t)*(1-t)*718 + 2*(1-t)*t*782 + t*t*782,
			(1-t)*(1-t)*222 + 2*(1-t)*t*222 + t*t*286,
		})
	}
	// 右侧下沉弧线到圆角底部尖端
	c1, c2, c3 := pt{782, 616}, pt{672, 764}, pt{548, 830}
	const m = 48
	for i := 1; i <= m; i++ {
		t := float64(i) / m
		u := 1 - t
		poly = append(poly, pt{
			u*u*u*782 + 3*u*u*t*c1.x + 3*u*t*t*c2.x + t*t*t*c3.x,
			u*u*u*470 + 3*u*u*t*c1.y + 3*u*t*t*c2.y + t*t*t*c3.y,
		})
	}
	// 底部尖端圆角 Q(512,846)->(476,830)
	for i := 1; i <= n; i++ {
		t := float64(i) / n
		poly = append(poly, pt{
			(1-t)*(1-t)*548 + 2*(1-t)*t*512 + t*t*476,
			(1-t)*(1-t)*830 + 2*(1-t)*t*846 + t*t*830,
		})
	}
	// 左侧对称弧线回到 (242,470)
	d1, d2, d3 := pt{352, 764}, pt{242, 616}, pt{242, 470}
	for i := 1; i <= m; i++ {
		t := float64(i) / m
		u := 1 - t
		poly = append(poly, pt{
			u*u*u*476 + 3*u*u*t*d1.x + 3*u*t*t*d2.x + t*t*t*d3.x,
			u*u*u*830 + 3*u*u*t*d1.y + 3*u*t*t*d2.y + t*t*t*d3.y,
		})
	}
	return poly
}

// stemPath 展平钥匙孔的梯形杆。
func stemPath() []pt {
	poly := []pt{{452, 508}, {572, 508}, {596, 676}}
	const n = 16
	for i := 1; i <= n; i++ { // 右下角 Q(596,706)->(566,706)
		t := float64(i) / n
		poly = append(poly, pt{
			(1-t)*(1-t)*596 + 2*(1-t)*t*596 + t*t*566,
			(1-t)*(1-t)*676 + 2*(1-t)*t*706 + t*t*706,
		})
	}
	poly = append(poly, pt{458, 706})
	for i := 1; i <= n; i++ { // 左下角 Q(428,706)->(428,676) 逆向回到起点
		t := float64(i) / n
		poly = append(poly, pt{
			(1-t)*(1-t)*458 + 2*(1-t)*t*428 + t*t*428,
			(1-t)*(1-t)*706 + 2*(1-t)*t*706 + t*t*676,
		})
	}
	return poly
}

// spansFor 计算多边形在扫描线 y 上的填充区间（偶奇规则）。
func spansFor(poly []pt, y float64) [][2]float64 {
	var xs []float64
	n := len(poly)
	for i := 0; i < n; i++ {
		a, b := poly[i], poly[(i+1)%n]
		if a.y == b.y {
			continue
		}
		lo, hi := a.y, b.y
		if lo > hi {
			lo, hi = hi, lo
		}
		if y >= lo && y < hi {
			t := (y - a.y) / (b.y - a.y)
			xs = append(xs, a.x+t*(b.x-a.x))
		}
	}
	sortF := func(s []float64) {
		for i := 1; i < len(s); i++ {
			for j := i; j > 0 && s[j] < s[j-1]; j-- {
				s[j], s[j-1] = s[j-1], s[j]
			}
		}
	}
	sortF(xs)
	var spans [][2]float64
	for i := 0; i+1 < len(xs); i += 2 {
		spans = append(spans, [2]float64{xs[i], xs[i+1]})
	}
	return spans
}

func inSpans(spans [][2]float64, x float64) bool {
	for _, s := range spans {
		if x >= s[0] && x < s[1] {
			return true
		}
	}
	return false
}

func inRoundedTile(x, y float64) bool {
	r := tileRad
	if x < r && y < r && (x-r)*(x-r)+(y-r)*(y-r) > r*r {
		return false
	}
	if x > size-r && y < r && (x-(size-r))*(x-(size-r))+(y-r)*(y-r) > r*r {
		return false
	}
	if x < r && y > size-r && (x-r)*(x-r)+(y-(size-r))*(y-(size-r)) > r*r {
		return false
	}
	if x > size-r && y > size-r && (x-(size-r))*(x-(size-r))+(y-(size-r))*(y-(size-r)) > r*r {
		return false
	}
	return x >= 0 && y >= 0 && x <= size && y <= size
}

func over(base [4]float64, top [4]float64) [4]float64 {
	a := top[3]
	return [4]float64{
		top[0]*a + base[0]*(1-a),
		top[1]*a + base[1]*(1-a),
		top[2]*a + base[2]*(1-a),
		math.Min(1, base[3]+a),
	}
}

func main() {
	N := size * supersam
	shield := shieldPath()
	stem := stemPath()
	const (
		circCX, circCY, circR  = 512.0, 452.0, 88.0        // 钥匙孔圆
		shCX, shCY, shRX, shRY = 512.0, 880.0, 300.0, 46.0 // 投影椭圆
	)

	// 预计算所有超采样行的多边形区间（盾牌 + 键孔杆）
	shieldSpans := make([][][2]float64, N)
	stemSpans := make([][][2]float64, N)
	for py := 0; py < N; py++ {
		y := (float64(py) + 0.5) / supersam
		shieldSpans[py] = spansFor(shield, y)
		stemSpans[py] = spansFor(stem, y)
	}

	buf := image.NewRGBA(image.Rect(0, 0, N, N))
	for py := 0; py < N; py++ {
		yc := (float64(py) + 0.5) / supersam
		for px := 0; px < N; px++ {
			xc := (float64(px) + 0.5) / supersam
			var c [4]float64 // RGBA 0..1

			if inRoundedTile(xc, yc) {
				g := grad(tileTop, tileBottom, yc)
				c = [4]float64{g[0] / 255, g[1] / 255, g[2] / 255, 1}
				// 盾牌投影
				dx := (xc - shCX) / shRX
				dy := (yc - shCY) / shRY
				if dx*dx+dy*dy <= 1 {
					s := shadowCol
					c = over(c, [4]float64{s[0] / 255, s[1] / 255, s[2] / 255, s[3]})
				}
			}

			// 盾牌主体（白色渐变）
			if inSpans(shieldSpans[py], xc) {
				g := grad(shieldTop, shieldBot, yc)
				c = [4]float64{g[0] / 255, g[1] / 255, g[2] / 255, 1}
				// 镂空钥匙孔 = 贴片同款渐变（视觉穿透）
				dxc, dyc := xc-circCX, yc-circCY
				if dxc*dxc+dyc*dyc <= circR*circR || inSpans(stemSpans[py], xc) {
					g2 := grad(tileTop, tileBottom, yc)
					c = [4]float64{g2[0] / 255, g2[1] / 255, g2[2] / 255, 1}
				}
			}

			i := (py*N + px) * 4
			buf.Pix[i] = uint8(math.Min(255, c[0]*255+0.5))
			buf.Pix[i+1] = uint8(math.Min(255, c[1]*255+0.5))
			buf.Pix[i+2] = uint8(math.Min(255, c[2]*255+0.5))
			buf.Pix[i+3] = uint8(math.Min(255, c[3]*255+0.5))
		}
	}

	full := downscale(buf, size)

	// appicon.png (1024)
	if err := savePNG(full, outPng); err != nil {
		panic(err)
	}

	// icon.ico 多尺寸
	if err := saveICO(full, outIco); err != nil {
		panic(err)
	}
}

// downscale 4x4 盒滤波降采样到 size。
func downscale(src *image.RGBA, target int) *image.RGBA {
	S := src.Rect.Dx() / target
	out := image.NewRGBA(image.Rect(0, 0, target, target))
	inv := 1.0 / float64(S*S)
	for y := 0; y < target; y++ {
		for x := 0; x < target; x++ {
			var r, g, b, a float64
			for dy := 0; dy < S; dy++ {
				for dx := 0; dx < S; dx++ {
					i := ((y*S+dy)*src.Rect.Dx() + x*S + dx) * 4
					r += float64(src.Pix[i])
					g += float64(src.Pix[i+1])
					b += float64(src.Pix[i+2])
					a += float64(src.Pix[i+3])
				}
			}
			o := (y*target + x) * 4
			out.Pix[o] = uint8(r*inv + 0.5)
			out.Pix[o+1] = uint8(g*inv + 0.5)
			out.Pix[o+2] = uint8(b*inv + 0.5)
			out.Pix[o+3] = uint8(a*inv + 0.5)
		}
	}
	return out
}

func resizeArea(src *image.RGBA, target int) *image.RGBA {
	return downscale(src, target)
}

func savePNG(img image.Image, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

// saveICO 写多尺寸 ICO（全部条目用 PNG 编码，Vista+/Win11 支持）。
func saveICO(base *image.RGBA, path string) error {
	var entries [][]byte
	for _, s := range icoSizes {
		var buf bytes.Buffer
		img := resizeArea(base, s)
		if err := png.Encode(&buf, img); err != nil {
			return err
		}
		entries = append(entries, buf.Bytes())
	}

	var out bytes.Buffer
	header := make([]byte, 6)
	binary.LittleEndian.PutUint16(header[0:], 0) // reserved
	binary.LittleEndian.PutUint16(header[2:], 1) // type: icon
	binary.LittleEndian.PutUint16(header[4:], uint16(len(entries)))
	out.Write(header)

	offset := 6 + 16*len(entries)
	for i, s := range icoSizes {
		e := make([]byte, 16)
		if s >= 256 {
			e[0], e[1] = 0, 0 // 256 = 0
		} else {
			e[0], e[1] = byte(s), byte(s)
		}
		e[2], e[3] = 0, 0                        // 调色板数 / 保留
		binary.LittleEndian.PutUint16(e[4:], 1)  // planes
		binary.LittleEndian.PutUint16(e[6:], 32) // bpp
		binary.LittleEndian.PutUint32(e[8:], uint32(len(entries[i])))
		binary.LittleEndian.PutUint32(e[12:], uint32(offset))
		out.Write(e)
		offset += len(entries[i])
	}
	for _, d := range entries {
		out.Write(d)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}
