package applogo

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math/bits"
	"strconv"
)

const hashSide = 8

func validatePNG(body []byte) (*Logo, error) {
	if len(body) > MaxPNGBytes {
		return nil, invalid("a PNG logo is at most %d KB", MaxPNGBytes>>10)
	}
	config, err := png.DecodeConfig(bytes.NewReader(body))
	if err != nil {
		return nil, invalid("the PNG cannot be read")
	}
	if err := checkPNGDimensions(config); err != nil {
		return nil, err
	}
	decoded, err := png.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, invalid("the PNG cannot be read")
	}
	var normalized bytes.Buffer
	if err := png.Encode(&normalized, decoded); err != nil {
		return nil, invalid("the PNG cannot be re-encoded")
	}
	return newLogo(ContentTypePNG, normalized.Bytes(), averageHash(decoded)), nil
}

func checkPNGDimensions(config image.Config) error {
	width, height := config.Width, config.Height
	if width < MinDimension || height < MinDimension || width > MaxDimension || height > MaxDimension {
		return invalid("a PNG logo is between %d and %d pixels on each side", MinDimension, MaxDimension)
	}
	if width > height*maxAspectRatio || height > width*maxAspectRatio {
		return invalid("a logo is at most %d times wider than tall", maxAspectRatio)
	}
	return nil
}

// averageHash is the 64-bit average hash of the picture as 16 hex digits: the
// picture is reduced to 8x8 gray cells over a white background and each bit
// says whether a cell is brighter than the mean.
func averageHash(picture image.Image) string {
	cells := grayCells(picture)
	var total float64
	for _, cell := range cells {
		total += cell
	}
	mean := total / float64(len(cells))
	var hash uint64
	for index, cell := range cells {
		if cell > mean {
			hash |= 1 << uint(index)
		}
	}
	return strconv.FormatUint(hash, 16)
}

func grayCells(picture image.Image) []float64 {
	bounds := picture.Bounds()
	cells := make([]float64, hashSide*hashSide)
	counts := make([]float64, hashSide*hashSide)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			cell := (y-bounds.Min.Y)*hashSide/bounds.Dy()*hashSide + (x-bounds.Min.X)*hashSide/bounds.Dx()
			cells[cell] += grayOverWhite(picture.At(x, y))
			counts[cell]++
		}
	}
	for index := range cells {
		cells[index] /= counts[index]
	}
	return cells
}

func grayOverWhite(pixel color.Color) float64 {
	red, green, blue, alpha := pixel.RGBA()
	const full = 65535.0
	opacity := float64(alpha) / full
	gray := 0.299*float64(red) + 0.587*float64(green) + 0.114*float64(blue)
	return gray/full + (1 - opacity)
}

// MaxLookalikeDistance is the largest Hamming distance between two average
// hashes at which two PNG logos count as the same picture.
const MaxLookalikeDistance = 6

// Resembles reports whether two logos look like the same picture: identical
// bytes, or PNGs whose average hashes are within MaxLookalikeDistance bits.
func Resembles(firstSHA256 string, firstAHash string, secondSHA256 string, secondAHash string) bool {
	if firstSHA256 == secondSHA256 {
		return true
	}
	first, firstErr := strconv.ParseUint(firstAHash, 16, 64)
	second, secondErr := strconv.ParseUint(secondAHash, 16, 64)
	if firstErr != nil || secondErr != nil {
		return false
	}
	return bits.OnesCount64(first^second) <= MaxLookalikeDistance
}
