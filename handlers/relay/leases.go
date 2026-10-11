package relay

// leaseKey names the Redis set that caps the caller's open connections: one per
// signed-in user of a client, one per IP for anonymous connections.
func leaseKey(who identity) string {
	if who.signedIn() {
		return "relay:connections:user:" + channelName(who.clientID, who.userID)
	}
	return "relay:connections:ip:" + who.ip
}
