package database

import (
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	maxFacetsPerNode = 64
	// Facet tags are protobuf field numbers: 1 is the default facet, named
	// facets derive theirs below 2^29.
	maxFacetTag  = 1<<29 - 1
	wireTypeLen  = 2
	maxVarintLen = 10
)

// ContentFacetTags checks that content is base64url of one message holding a
// LEN field per facet, in strictly ascending tag order, each with a non-empty
// body, and returns the tags. Empty content has no facets.
func ContentFacetTags(content string) ([]int, error) {
	bytes, err := base64.RawURLEncoding.Strict().DecodeString(content)
	if err != nil {
		return nil, errors.New("content must be base64url without padding")
	}
	tags := []int{}
	for len(bytes) > 0 {
		tag, rest, err := readFacetField(bytes)
		if err != nil {
			return nil, err
		}
		if len(tags) > 0 && tag <= tags[len(tags)-1] {
			return nil, errors.New("content facets must be in ascending tag order")
		}
		tags = append(tags, tag)
		bytes = rest
	}
	if len(tags) > maxFacetsPerNode {
		return nil, fmt.Errorf("a node has at most %d facets", maxFacetsPerNode)
	}
	return tags, nil
}

// readFacetField reads one `tag*8+2, length, body` field and returns the tag
// and the bytes after it.
func readFacetField(bytes []byte) (int, []byte, error) {
	key, afterKey, ok := readVarint(bytes)
	if !ok || key&7 != wireTypeLen {
		return 0, nil, errors.New("content facets must be length-delimited fields")
	}
	tag := key >> 3
	if tag < 1 || tag > maxFacetTag {
		return 0, nil, errors.New("content facet tag is out of range")
	}
	length, body, ok := readVarint(afterKey)
	if !ok || length == 0 || length > uint64(len(body)) {
		return 0, nil, errors.New("content facet length is invalid")
	}
	return int(tag), body[length:], nil
}

func readVarint(bytes []byte) (uint64, []byte, bool) {
	var value uint64
	for index := 0; index < len(bytes) && index < maxVarintLen; index++ {
		if index == maxVarintLen-1 && bytes[index] > 1 {
			return 0, nil, false
		}
		value |= uint64(bytes[index]&0x7f) << (7 * index)
		if bytes[index] < 0x80 {
			return value, bytes[index+1:], true
		}
	}
	return 0, nil, false
}
