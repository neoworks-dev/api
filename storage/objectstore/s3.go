package objectstore

import (
	"bytes"
	"context"
	"fmt"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Store struct {
	client *minio.Client
	bucket string
}

func New(endpoint, accessKey, secretKey, bucket string, useSSL bool) (*Store, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("minio client: %w", err)
	}
	return &Store{client: client, bucket: bucket}, nil
}

// EnsureBucket creates the bucket if it does not already exist.
func (s *Store) EnsureBucket(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("check bucket: %w", err)
	}
	if exists {
		return nil
	}
	return s.client.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{})
}

// PutChunk uploads raw bytes under a per-user content-addressed key.
// Scoping by userID ensures chunks from different users (different AMKs) never collide.
// Returns the storage key on success.
func (s *Store) PutChunk(ctx context.Context, userID, hash string, data []byte) (string, error) {
	key := chunkKey(userID, hash)
	_, err := s.client.PutObject(ctx, s.bucket, key,
		bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: "application/octet-stream"},
	)
	if err != nil {
		return "", fmt.Errorf("put chunk %s: %w", hash, err)
	}
	return key, nil
}

// GetChunk streams the raw bytes of a previously stored chunk.
// Caller must close the returned object.
func (s *Store) GetChunk(ctx context.Context, storageKey string) (*minio.Object, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, storageKey, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("get chunk %s: %w", storageKey, err)
	}
	return obj, nil
}

// DeleteChunk removes a chunk's blob from object storage.
func (s *Store) DeleteChunk(ctx context.Context, storageKey string) error {
	if err := s.client.RemoveObject(ctx, s.bucket, storageKey, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("delete chunk %s: %w", storageKey, err)
	}
	return nil
}

// PutObject uploads raw bytes under an arbitrary key with the given content type.
// Used for non-chunked assets (e.g. logos, documents) served by the assets service.
func (s *Store) PutObject(ctx context.Context, key string, data []byte, contentType string) error {
	_, err := s.client.PutObject(ctx, s.bucket, key,
		bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: contentType},
	)
	if err != nil {
		return fmt.Errorf("put object %s: %w", key, err)
	}
	return nil
}

// GetObject streams the raw bytes stored under an arbitrary key.
// Caller must close the returned object.
func (s *Store) GetObject(ctx context.Context, key string) (*minio.Object, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("get object %s: %w", key, err)
	}
	return obj, nil
}

// ChunkKey returns the storage key for a given user + hash (exported for tests).
func ChunkKey(userID, hash string) string { return chunkKey(userID, hash) }

// chunkKey shards by first four hex characters to keep prefix lists short.
func chunkKey(userID, hash string) string {
	return fmt.Sprintf("chunks/%s/%s/%s/%s", userID, hash[0:2], hash[2:4], hash)
}
