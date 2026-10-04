package database

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/neoworks/auth/utils"
)

const (
	maxBlobChunks   = 262144
	maxBlobVariants = 8
)

// BlobVariant is an additional encrypted rendition of a node's blob, such as a thumbnail.
type BlobVariant struct {
	Name     string `json:"name"`
	ObjectID string `json:"objectId"`
	Chunks   int    `json:"chunks"`
	Size     int64  `json:"size"`
}

// BlobReference points at the encrypted chunks of a node's file in object
// storage. Chunk i of an object lives under the key "<objectId>/<i>".
type BlobReference struct {
	ObjectID string        `json:"objectId"`
	Chunks   int           `json:"chunks"`
	Size     int64         `json:"size"`
	Variants []BlobVariant `json:"variants"`
}

// ParseBlobReference decodes and validates the blob JSON of a node. It also
// returns the compact JSON to store, which is what the author signed.
func ParseBlobReference(raw json.RawMessage) (*BlobReference, []byte, error) {
	var reference BlobReference
	if err := json.Unmarshal(raw, &reference); err != nil {
		return nil, nil, fmt.Errorf("blob is not valid JSON: %w", err)
	}
	if err := reference.validate(); err != nil {
		return nil, nil, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, nil, err
	}
	return &reference, compact.Bytes(), nil
}

func (reference *BlobReference) validate() error {
	if len(reference.Variants) > maxBlobVariants {
		return fmt.Errorf("a blob has at most %d variants", maxBlobVariants)
	}
	seenObjects := map[string]bool{}
	for _, object := range reference.objects() {
		if err := validateBlobObject(object, seenObjects); err != nil {
			return err
		}
	}
	return nil
}

type blobObject struct {
	objectID string
	chunks   int
	size     int64
}

func (reference *BlobReference) objects() []blobObject {
	objects := []blobObject{{reference.ObjectID, reference.Chunks, reference.Size}}
	for _, variant := range reference.Variants {
		objects = append(objects, blobObject{variant.ObjectID, variant.Chunks, variant.Size})
	}
	return objects
}

func validateBlobObject(object blobObject, seenObjects map[string]bool) error {
	if !utils.IsLowercaseUUIDv4(object.objectID) {
		return errors.New("blob objectId must be a lowercase UUIDv4")
	}
	if seenObjects[object.objectID] {
		return errors.New("blob objectIds must be unique")
	}
	seenObjects[object.objectID] = true
	if object.chunks < 1 || object.chunks > maxBlobChunks {
		return fmt.Errorf("blob chunks must be between 1 and %d", maxBlobChunks)
	}
	if object.size < 0 {
		return errors.New("blob size must not be negative")
	}
	return nil
}

// ObjectIDs lists the original's object id followed by every variant's.
func (reference *BlobReference) ObjectIDs() []string {
	ids := []string{}
	for _, object := range reference.objects() {
		ids = append(ids, object.objectID)
	}
	return ids
}

// TotalSize is the stored byte count of the original and all variants.
func (reference *BlobReference) TotalSize() int64 {
	var total int64
	for _, object := range reference.objects() {
		total += object.size
	}
	return total
}

// ChunkCount returns the number of chunks of one of the blob's objects.
func (reference *BlobReference) ChunkCount(objectID string) (int, bool) {
	for _, object := range reference.objects() {
		if object.objectID == objectID {
			return object.chunks, true
		}
	}
	return 0, false
}
