package relay

import "encoding/json"

// Frame types sent by clients.
const (
	frameSubscribe   = "subscribe"
	frameUnsubscribe = "unsubscribe"
	framePublish     = "publish"
)

// Frame types sent by the server.
const (
	frameSubscribed   = "subscribed"
	frameUnsubscribed = "unsubscribed"
	frameMessage      = "message"
	frameError        = "error"
)

// Error codes of error frames.
const (
	codeInvalidFrame      = "invalid_frame"
	codeInvalidTopic      = "invalid_topic"
	codeMessageTooLarge   = "message_too_large"
	codeSubscriptionLimit = "subscription_limit"
	codeRateLimited       = "rate_limited"
	codeUnavailable       = "unavailable"
)

type clientFrame struct {
	Type  string `json:"type"`
	Topic string `json:"topic"`
	Data  string `json:"data"`
}

type messageFrame struct {
	Type  string `json:"type"`
	Topic string `json:"topic"`
	Data  string `json:"data"`
}

type statusFrame struct {
	Type  string `json:"type"`
	Topic string `json:"topic"`
}

type errorFrame struct {
	Type       string `json:"type"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	Topic      string `json:"topic,omitempty"`
	RetryAfter int    `json:"retryAfter,omitempty"`
}

func encodeMessage(topic string, data string) []byte {
	encoded, _ := json.Marshal(messageFrame{Type: frameMessage, Topic: topic, Data: data})
	return encoded
}

func encodeStatus(frameType string, topic string) []byte {
	encoded, _ := json.Marshal(statusFrame{Type: frameType, Topic: topic})
	return encoded
}

func encodeError(code string, message string, topic string, retryAfterSeconds int) []byte {
	encoded, _ := json.Marshal(errorFrame{Type: frameError, Code: code, Message: message, Topic: topic, RetryAfter: retryAfterSeconds})
	return encoded
}
