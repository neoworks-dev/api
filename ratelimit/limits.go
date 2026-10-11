// Package ratelimit limits how often a client, a user of a client and an
// anonymous caller may call the API. Counters live in Redis so every instance
// enforces the same limits; the limits of a client scale with its standing.
package ratelimit

import (
	"time"

	"github.com/neoworks/auth/storage/database"
)

// Bucket is a kind of call that is limited on its own.
type Bucket string

const (
	BucketSync         Bucket = "sync"
	BucketPush         Bucket = "push"
	BucketBlobUpload   Bucket = "blob_upload"
	BucketBlobDownload Bucket = "blob_download"
	BucketIdentity     Bucket = "identity"
	BucketGeneral      Bucket = "general"
	// BucketPublic and BucketAssets limit callers without a token, by IP.
	BucketPublic Bucket = "public"
	BucketAssets Bucket = "assets"
)

// Window is the length of the counting window of every limit.
const Window = time.Minute

// Limit is the calls allowed per Window: for a client as a whole, for one user
// of it, and for one IP when the caller has no token.
type Limit struct {
	PerClient     int
	PerUserClient int
	PerIP         int
}

// DefaultLimits are the limits of a client that has not been reviewed or
// verified. Reads are generous because sync polls; uploads and identity lookups
// are the expensive calls.
var DefaultLimits = map[Bucket]Limit{
	BucketSync:         {PerClient: 6000, PerUserClient: 600},
	BucketPush:         {PerClient: 3000, PerUserClient: 300},
	BucketBlobUpload:   {PerClient: 1200, PerUserClient: 120},
	BucketBlobDownload: {PerClient: 6000, PerUserClient: 600},
	BucketIdentity:     {PerClient: 1200, PerUserClient: 120},
	BucketGeneral:      {PerClient: 6000, PerUserClient: 600},
	BucketPublic:       {PerIP: 120},
	BucketAssets:       {PerIP: 600},
}

// Multipliers scale the limits of a client by its standing.
const (
	MultiplierDefault  = 1.0
	MultiplierVerified = 2.0
	MultiplierApproved = 3.0
	MultiplierBoth     = 4.0
	MultiplierOfficial = 20.0
)

// MultiplierFor is the factor applied to the limits of a client: the one an
// operator set, otherwise what its first-party, verified and reviewed standing
// earns.
func MultiplierFor(standing *database.ClientStanding) float64 {
	if standing.Multiplier != nil {
		return *standing.Multiplier
	}
	if standing.FirstParty {
		return MultiplierOfficial
	}
	approved := standing.ReviewStatus == database.ReviewStatusApproved
	switch {
	case approved && standing.Verified:
		return MultiplierBoth
	case approved:
		return MultiplierApproved
	case standing.Verified:
		return MultiplierVerified
	}
	return MultiplierDefault
}

func scaled(limit int, multiplier float64) int {
	scaledLimit := int(float64(limit) * multiplier)
	if scaledLimit < 1 {
		return 1
	}
	return scaledLimit
}
