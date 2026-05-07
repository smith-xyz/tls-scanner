package stringutil

// RemoveDuplicates returns a new slice with duplicates and empty strings removed,
// preserving the original order.
func RemoveDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	for _, item := range slice {
		if !keys[item] && item != "" {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}
