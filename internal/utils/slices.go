package utils

// SliceMap performs a specified function to every element in the specified slice. Emulates the `map` function in functional programming languages
func SliceMap[T, U any](data []T, f func(T) U) []U {
	res := make([]U, 0, len(data))
	for _, element := range data {
		res = append(res, f(element))
	}
	return res
}
