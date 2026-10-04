package objectstore

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Store struct {
	client *minio.Client
	// signer produces presigned URLs. It is built for the endpoint browsers
	// reach, which can differ from the one the API talks to.
	signer *minio.Client
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
	return &Store{client: client, signer: client, bucket: bucket}, nil
}

// signingRegion avoids the bucket-location round trip when presigning, which
// would otherwise need to reach the public endpoint from the server.
const signingRegion = "us-east-1"

// UsePublicEndpoint makes presigned URLs point at the endpoint clients can reach.
func (s *Store) UsePublicEndpoint(endpoint, accessKey, secretKey string, useSSL bool) error {
	signer, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
		Region: signingRegion,
	})
	if err != nil {
		return fmt.Errorf("minio signer: %w", err)
	}
	s.signer = signer
	return nil
}

// PresignPut returns a URL that uploads one object without passing through the API.
func (s *Store) PresignPut(ctx context.Context, key string, expiry time.Duration) (string, error) {
	presigned, err := s.signer.PresignedPutObject(ctx, s.bucket, key, expiry)
	if err != nil {
		return "", fmt.Errorf("presign put %s: %w", key, err)
	}
	return presigned.String(), nil
}

// PresignGet returns a URL that downloads one object without passing through the API.
func (s *Store) PresignGet(ctx context.Context, key string, expiry time.Duration) (string, error) {
	presigned, err := s.signer.PresignedGetObject(ctx, s.bucket, key, expiry, nil)
	if err != nil {
		return "", fmt.Errorf("presign get %s: %w", key, err)
	}
	return presigned.String(), nil
}

// RemovePrefix deletes every object whose key starts with prefix.
func (s *Store) RemovePrefix(ctx context.Context, prefix string) error {
	objects := s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true})
	for object := range objects {
		if object.Err != nil {
			return fmt.Errorf("list %s: %w", prefix, object.Err)
		}
		if err := s.client.RemoveObject(ctx, s.bucket, object.Key, minio.RemoveObjectOptions{}); err != nil {
			return fmt.Errorf("remove %s: %w", object.Key, err)
		}
	}
	return nil
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
