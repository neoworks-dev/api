package dbtest

// Content frames ciphertext as the default facet (tag 1) of a node's content,
// as clients do; the server only checks the framing.
func Content(ciphertext string) string {
	return encoding.EncodeToString(FacetField(1, []byte(ciphertext)))
}

// FacetField is one LEN field of node content: key tag*8+2, length, body.
func FacetField(tag int, body []byte) []byte {
	field := appendVarint(nil, uint64(tag)*8+2)
	field = appendVarint(field, uint64(len(body)))
	return append(field, body...)
}

func appendVarint(bytes []byte, value uint64) []byte {
	for value >= 0x80 {
		bytes = append(bytes, byte(value)|0x80)
		value >>= 7
	}
	return append(bytes, byte(value))
}
