package grok

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Edge struct {
	From, To string
}

type Lattice struct {
	Name  string
	Edges []Edge
}

// parse a string to lattice structure
// the input string should follow below format
// {
//  "name": "DataType"
//  "edges": {
//      "UniqueID": ["AccountID", "IPAddress"],
//      "Location": ["IPAddress"]
//  }
// }
// it will generate a lattice as:
//               TOP
//              /   \
//       UniqueID   Location
//           /   \    /
//   AccountID   IPAddress
//          \     /
//          BOTTOM

func ParseJSON(m map[string]interface{}) Lattice {
	name := m["name"].(string)
	edges := m["edges"].(map[string]interface{})

	var es []Edge
	sps := make([]string, 0)     // single-points in JSON defintions
	for ef, ets := range edges { // edge_from, edge_tos
		if len(ets.([]interface{})) == 0 {
			sps = append(sps, ef)
			continue
		}
		for _, to := range ets.([]interface{}) {
			// fmt.Printf("%s ==> %s %T\n", ef, to, to)
			es = append(es, Edge{ef, to.(string)})
		}
	}

	// append edges from TOP, and edges to BOTTOM
	froms := make([]string, 0)
	tos := make([]string, 0)
	for _, edge := range es {
		if !contains(froms, edge.From) {
			froms = append(froms, edge.From)
		}
		if !contains(tos, edge.To) {
			tos = append(tos, edge.To)
		}
	}

	for _, f := range froms {
		if !contains(tos, f) {
			es = append(es, Edge{"TOP", f})
		}
	}
	for _, t := range tos {
		if !contains(froms, t) {
			es = append(es, Edge{t, "BOTTOM"})
		}
	}

	for _, sp := range sps {
		es = append(es, Edge{"TOP", sp})
		es = append(es, Edge{sp, "BOTTOM"})
	}

	return Lattice{name, es}
}

// NewLattice create a Lattice instance from a string
func NewLattice(str string) Lattice {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(str), &result); err != nil {
		fmt.Println(err)
	}

	lattice := ParseJSON(result)
	return lattice
}

// NewLattices create a Lattice array from a string
func NewLattices(str string) []Lattice {
	var result []map[string]interface{}
	if err := json.Unmarshal([]byte(str), &result); err != nil {
		fmt.Println(err)
	}
	lattices := make([]Lattice, 0)
	for _, m := range result {
		lattices = append(lattices, ParseJSON(m))
	}
	return lattices
}

func (l Lattice) ToString() string {
	return "Hello, Lattice"
}

func (l Lattice) childrenOf(nodes []string) []string {
	ch := make([]string, 0)
	for _, e := range l.Edges {
		if contains(nodes, e.From) {
			ch = append(ch, e.To)
		}
	}
	sort.Slice(ch, func(p, q int) bool {
		return strings.Compare(ch[p], ch[q]) == -1
	})
	return ch
}

// Meet: greated lower bound, infimum, a ^ b
func (l Lattice) Meet(a, b string) string {
	nodea := []string{a}
	nodeb := []string{b}
	res := make([]string, 0)

	for len(res) != 1 {
		if len(res) != 0 {
			res = res[0:0]
		}
		for _, e := range nodea {
			if contains(nodeb, e) {
				res = append(res, e)
			}
		}
		if len(res) != 1 {
			nodea, nodeb = nodeb, append(nodea, l.childrenOf(nodea)...)
		} else {
			break
		}
	}
	return res[0]
}

func (l Lattice) parentsOf(nodes []string) []string {
	pa := make([]string, 0)
	for _, e := range l.Edges {
		if contains(nodes, e.To) && !contains(pa, e.From) {
			pa = append(pa, e.From)
		}
	}
	sort.Slice(pa, func(p, q int) bool {
		return strings.Compare(pa[p], pa[q]) == -1
	})
	return pa
}

// Join: least upper bound, supremum, a ∨ b
func (l Lattice) Join(a, b string) string {
	nodea := []string{a}
	nodeb := []string{b}
	res := make([]string, 0)

	for len(res) != 1 {
		if len(res) != 0 {
			res = res[0:0]
		}
		for _, e := range nodea {
			if contains(nodeb, e) {
				res = append(res, e)
			}
		}
		if len(res) != 1 {
			nodea, nodeb = nodeb, append(nodea, l.parentsOf(nodea)...)
		} else {
			break
		}
	}
	return res[0]
}

func (l Lattice) Precede(a, b string) bool {
	pa := []string{b}

	for {
		if len(pa) == 1 && pa[0] == "BOTTOM" {
			return false
		} else if contains(pa, a) {
			return true
		} else {
			pa = l.childrenOf(pa)
		}
	}
}

// Allow policy clause T[c] applies to annotation attributes
func (l Lattice) Allow(pattrs, aattrs []string) bool {
	for _, aattr := range aattrs {
		allowed := false
		for _, pattr := range pattrs {
			if l.Precede(aattr, pattr) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

// overlap of attributes in policy and annotations (Tₓ ⨅ T'ₓ from paper)
func (l Lattice) overlap(pattrs, aattrs []string) []string {
	res := make([]string, 0)
	if len(aattrs) == 0 {
		return res
	}
	for _, pattr := range pattrs {
		var r string
		for i, aattr := range aattrs {
			if i == 0 {
				r = l.Meet(pattr, aattr)
			} else {
				r = l.Join(r, l.Meet(pattr, aattr))
			}
		}
		res = append(res, r)
	}
	return res
}

// Deny policy clause T[c] applies (⊥ ∉ Tₓ from paper)
func (l Lattice) Deny(pattrs, aattrs []string) bool {
	overlaps := l.overlap(pattrs, aattrs)
	for _, ol := range overlaps {
		if ol == "BOTTOM" {
			return false
		}
	}
	return true
}

func contains(arr []string, str string) bool {
	for _, e := range arr {
		if e == str {
			return true
		}
	}
	return false
}
