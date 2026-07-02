package shared

func ContainsURI(list []string, target string) bool {
	for _, u := range list {
		if u == target {
			return true
		}
	}
	return false
}
