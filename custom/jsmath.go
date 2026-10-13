// Math.log2 de JavaScript, au bit près.
//
// Copie de jsLog2 de detect/jsstring.go (portage de __ieee754_log2 de FreeBSD, implémentation de Math.log2 du moteur
// V8) : le seuil d'entropie des motifs compare une somme de p × log2(p) à minEntropyTenths / 10 ; un écart d'un bit avec
// math.Log2 changerait la comparaison au seuil.

package custom

import "math"

// Constantes de __ieee754_log2 (FreeBSD e_log2.c, k_log.h), l'implémentation de Math.log2 du moteur V8.
const (
	log2Two54  = 1.80143985094819840000e+16
	log2IvLn2H = 1.44269504072144627571e+00
	log2IvLn2L = 1.67517131648865118353e-10
	log2Lg1    = 6.666666666666735130e-01
	log2Lg2    = 3.999999999940941908e-01
	log2Lg3    = 2.857142874366239149e-01
	log2Lg4    = 2.222219843214978396e-01
	log2Lg5    = 1.818357216161805012e-01
	log2Lg6    = 1.531383769920937332e-01
	log2Lg7    = 1.479819860511658591e-01
)

// jsLog2 est Math.log2 de JavaScript (V8 : portage de FreeBSD e_log2.c), au bit près pour 0 < x ≤ 1, seul usage
// (probabilités de shannonEntropy) : un écart d'un bit avec math.Log2 changerait la comparaison au seuil d'entropie.
// Chaque produit est converti explicitement en float64, ce qui interdit au compilateur de le fusionner avec une
// addition (FMA sur arm64), comme V8 qui n'en fusionne aucun.
func jsLog2(x float64) float64 {
	bits := math.Float64bits(x)
	hx := int32(bits >> 32)
	lx := uint32(bits)
	k := int32(0)
	if hx < 0x00100000 {
		if (hx&0x7fffffff)|int32(lx) == 0 {
			return math.Inf(-1)
		}
		if hx < 0 {
			return math.NaN()
		}
		k -= 54
		x = float64(x * log2Two54)
		hx = int32(math.Float64bits(x) >> 32)
	}
	if hx >= 0x7ff00000 {
		return x + x
	}
	if hx == 0x3ff00000 && lx == 0 {
		return 0
	}
	k += (hx >> 20) - 1023
	hx &= 0x000fffff
	i := (hx + 0x95f64) & 0x100000
	x = math.Float64frombits(uint64(uint32(hx|(i^0x3ff00000)))<<32 | math.Float64bits(x)&0xffffffff)
	k += i >> 20
	y := float64(k)
	f := x - 1.0
	hfsq := float64(float64(0.5*f) * f)
	r := kLog1p(f)
	hi := f - hfsq
	hi = math.Float64frombits(math.Float64bits(hi) &^ 0xffffffff)
	lo := (f - hi) - hfsq + r
	valHi := float64(hi * log2IvLn2H)
	valLo := float64((lo+hi)*log2IvLn2L) + float64(lo*log2IvLn2H)
	w := y + valHi
	valLo += (y - w) + valHi
	valHi = w
	return valLo + valHi
}

// kLog1p est k_log1p de FreeBSD k_log.h.
func kLog1p(f float64) float64 {
	s := f / (2.0 + f)
	z := float64(s * s)
	w := float64(z * z)
	t1 := float64(w * (log2Lg2 + float64(w*(log2Lg4+float64(w*log2Lg6)))))
	t2 := float64(z * (log2Lg1 + float64(w*(log2Lg3+float64(w*(log2Lg5+float64(w*log2Lg7)))))))
	r := t2 + t1
	hfsq := float64(float64(0.5*f) * f)
	return float64(s * (hfsq + r))
}
