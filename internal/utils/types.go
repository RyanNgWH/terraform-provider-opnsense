package utils

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// BidirectionalMap is a map with both key-to-value and value-to-key lookups.
type BidirectionalMap struct {
	keyToValue map[string]string
	valueToKey map[string]string
	mutex      sync.RWMutex
}

// NewBidirectionalMap creates a new empty BidirectionalMap.
func NewBidirectionalMap() *BidirectionalMap {
	return &BidirectionalMap{
		keyToValue: make(map[string]string),
		valueToKey: make(map[string]string),
	}
}

// Put adds a key-value pair to the map and ensures the reverse mapping is updated.
func (bm *BidirectionalMap) Put(key, value string) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	// If the key already exists, delete the reverse mapping
	if existingValue, exists := bm.keyToValue[key]; exists {
		delete(bm.valueToKey, existingValue)
	}

	// If the value already exists, delete the reverse mapping
	if existingKey, exists := bm.valueToKey[value]; exists {
		delete(bm.keyToValue, existingKey)
	}

	// Insert the new key-value pair
	bm.keyToValue[key] = value
	bm.valueToKey[value] = key
}

// GetByKey retrieves the value associated with the given key.
func (bm *BidirectionalMap) GetByKey(key string) (string, bool) {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	value, exists := bm.keyToValue[key]
	return value, exists
}

// GetByValue retrieves the key associated with the given value.
func (bm *BidirectionalMap) GetByValue(value string) (string, bool) {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	key, exists := bm.valueToKey[value]
	return key, exists
}

// RemoveByKey removes the key-value pair from both directions.
func (bm *BidirectionalMap) RemoveByKey(key string) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	if value, exists := bm.keyToValue[key]; exists {
		delete(bm.keyToValue, key)
		delete(bm.valueToKey, value)
	}
}

// RemoveByValue removes the value-key pair from both directions.
func (bm *BidirectionalMap) RemoveByValue(value string) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	if key, exists := bm.valueToKey[value]; exists {
		delete(bm.keyToValue, key)
		delete(bm.valueToKey, value)
	}
}

// GetAllKeys returns a slice of all keys in the BidirectionalMap
func (bm *BidirectionalMap) GetAllKeys() []string {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	keys := make([]string, 0, len(bm.keyToValue))
	for key := range bm.keyToValue {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	return keys
}

// GetAllValues returns a slice of all values in the BidirectionalMap
func (bm *BidirectionalMap) GetAllValues() []string {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	values := make([]string, 0, len(bm.valueToKey))
	for value := range bm.keyToValue {
		values = append(values, value)
	}

	sort.Strings(values)
	return values
}

// Size returns the number of elements in the map.
func (bm *BidirectionalMap) Size() int {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()
	return len(bm.keyToValue)
}

// Set is an unordered collection of a single element type
type Set struct {
	elements map[string]struct{}
	mutex    sync.Mutex
}

// NewSet creates a new empty set
func NewSet() *Set {
	return &Set{elements: make(map[string]struct{})}
}

// Add adds an element to the set
func (s *Set) Add(value string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.elements[value] = struct{}{}
}

// AddSlice adds a slice of elements to the set
func (s *Set) AddSlice(slice []string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, element := range slice {
		s.elements[element] = struct{}{}
	}
}

// Remove removes an element from the set
func (s *Set) Remove(value string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.elements, value)
}

// Contains checks if an element is in the set
func (s *Set) Contains(value string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, exists := s.elements[value]
	return exists
}

// Size returns the number of elements in the set
func (s *Set) Size() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return len(s.elements)
}

// Clear removes all elements from the set
func (s *Set) Clear() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.elements = make(map[string]struct{})
}

// String outputs the contents of the set
func (s *Set) String() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var elements []string
	for key := range s.elements {
		elements = append(elements, key)
	}

	return fmt.Sprintf("{ %s }", strings.Join(elements, ", "))
}

// Elements returns a slice of all elements in the set
func (s *Set) Elements() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	elements := make([]string, 0, len(s.elements))
	for element := range s.elements {
		elements = append(elements, element)
	}

	sort.Strings(elements)
	return elements
}

// BoolToInt converts a `true` value to `1` and a `false` value to `0`.
func BoolToInt(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// StringListTerraformToGo converts a slice of terraform's `types.String` to a Go slice of strings.
func StringListTerraformToGo(terraformList []types.String) []string {
	result := make([]string, 0)
	for _, element := range terraformList {
		result = append(result, element.ValueString())
	}
	return result
}

// StringListGoToTerraform converts a Go slice of strings to a slice of terraform's `types.String`.
func StringListGoToTerraform(goList []string) []types.String {
	result := make([]types.String, 0)
	for _, element := range goList {
		result = append(result, types.StringValue(element))
	}
	return result
}

// SetTerraformToGo converts a Terraform set to a Go set.
func SetTerraformToGo(ctx context.Context, terraformSet types.Set) (*Set, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	result := NewSet()

	elements := make([]types.String, 0, len(terraformSet.Elements()))
	diags := terraformSet.ElementsAs(ctx, &elements, false)
	diagnostics.Append(diags...)

	result.AddSlice(StringListTerraformToGo(elements))

	return result, diagnostics
}

// SetGoToTerraform converts a Go set to a Terraform set
func SetGoToTerraform(ctx context.Context, goSet *Set) (types.Set, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	result, diags := basetypes.NewSetValueFrom(ctx, types.StringType, goSet.Elements())
	diagnostics.Append(diags...)

	return result, diagnostics
}
