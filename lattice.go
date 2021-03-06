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
	// Edges are the edge collections in lattice structure
	Edges []Edge
	// state is used to run cartesian product with current lattice. It can be seen
	// as the state of current lattice. For example, IPAddress:Truncated is a product
	// of two lattices, where IPAddress is from DataType lattice, and Truncated is
	// from TypeState lattice.
	state *Lattice
}

const (
	Top     = "TOP"     // the least upper bound (supremum) of a lattice
	Bottom  = "BOTTOM"  // the greatest lower bound (infimum) of a lattice
)

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

// NewLattice returns a Lattice instance that is parsed from a string
func NewLattice(str string) *Lattice {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(str), &result); err != nil {
		fmt.Println(err)
	}

	lattice := parse(result)
	return &lattice
}

// NewLattices returns a slice of Lattice instances that are parsed from a string
func NewLattices(str string) []*Lattice {
	var result []map[string]interface{}
	if err := json.Unmarshal([]byte(str), &result); err != nil {
		fmt.Println(err)
	}
	lattices := make([]*Lattice, 0)
	for _, m := range result {
		l := parse(m)
		lattices = append(lattices, &l)
	}
	return lattices
}

// parse returns a lattice instance after parsing a map structure (key-value pair from JSON)
func parse(m map[string]interface{}) Lattice {
	name := m["name"].(string)
	edgeMap := m["edges"].(map[string]interface{})

	var edges []Edge
	ses := make([]string, 0)     // singleton elements in JSON defintions
	for from, tos := range edgeMap { // edge_from, edge_tos
		if len(tos.([]interface{})) == 0 {
			ses = append(ses, from)
			continue
		}
		for _, to := range tos.([]interface{}) {
			edges = append(edges, Edge{from, to.(string)})
		}
	}

	// filter out "from" (i.e. "start") elements from all edges,
	// and filter out "to" (i.e. "end") elements from all edges
	froms := make([]string, 0)
	tos := make([]string, 0)
	for _, edge := range edges {
		if !contains(froms, edge.From) {
			froms = append(froms, edge.From)
		}
		if !contains(tos, edge.To) {
			tos = append(tos, edge.To)
		}
	}

	// append edges that are from TOP, and edges that are connected to BOTTOM
	for _, f := range froms {
		if !contains(tos, f) {
			edges = append(edges, Edge{Top, f})
		}
	}
	for _, t := range tos {
		if !contains(froms, t) {
			edges = append(edges, Edge{t, Bottom})
		}
	}

	// append edges that connects to singleton element
	for _, se := range ses {
		// edges = append(edges, Edge{"TOP", se})
		// edges = append(edges, Edge{se, "BOTTOM"})
		edges = append(edges, Edge{Top, se}, Edge{se, Bottom})
	}

	return Lattice{name, edges, nil}
}


// childrenOf returns children elements of input nodes (after removing duplicates)
func (l *Lattice) childrenOf(nodes []string) []string {
	ch := make([]string, 0)
	for _, e := range l.Edges {
		if contains(nodes, e.From) && !contains(ch, e.To) {
			ch = append(ch, e.To)
		}
	}
	sort.Slice(ch, func(p, q int) bool {
		return strings.Compare(ch[p], ch[q]) == -1
	})
	return ch
}

// Product sets its state lattice for current lattice. And the lattice still 
// keeps its behaviour as a single lattice
func (l *Lattice) Product(la *Lattice) {
	if la != nil {
		l.state = la
	}
}

func (l *Lattice) isProductValue(a string) bool {
	return l.state != nil && strings.ContainsRune(a, ':')
}

func (l *Lattice) halve(a string) (string, string) {
	if strings.ContainsRune(a, ':') {
		parts := strings.Split(a, ":")
		// assert len(parts) == 2
		return parts[0], parts[1]
	} else {
		return a, Top
	}
}

func (l *Lattice) combine(a, b string) string {
	if b == Top {
		return a
	} else {
		return a + ":" + b
	}
}


// Meet returns greated lower bound (infimum, a ^ b) of two elements a and b
func (l *Lattice) Meet(a, b string) string {
	// Meet operation for producted lattice
	if l.isProductValue(a) || l.isProductValue(b) {
		fsta, snda := l.halve(a)
		fstb, sndb := l.halve(b)
		return l.combine(l.Meet(fsta, fstb), l.state.Meet(snda, sndb))
	}

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
		if len(res) == 0 {
			ch := l.childrenOf(nodea)
			nodea, nodeb = nodeb, append(nodea,
				filter(ch, func(a string) bool { return !contains(nodea, a) })...)
		} else {
			if len(res) > 1 {
				sort.Slice(res, func(p, q int) bool {
					return l.Precede(res[p], res[q])
				})
			}
			break
		}
	}
	return res[0]
}

// parentsOf returns parents of a slice of elements in lattice (after removing duplicates)
func (l *Lattice) parentsOf(nodes []string) []string {
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

// Join returns the least upper bound (supremum, a ??? b) of two elements a and b
func (l *Lattice) Join(a, b string) string {
	// Join operation for producted lattice
	if l.isProductValue(a) || l.isProductValue(b) {
		fsta, snda := l.halve(a)
		fstb, sndb := l.halve(b)
		return l.combine(l.Join(fsta, fstb), l.state.Join(snda, sndb))
	}

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
		if len(res) == 0 {
			pa := l.parentsOf(nodea)
			nodea, nodeb = nodeb, append(nodea,
				filter(pa, func(a string) bool { return !contains(nodea, a) })...)
		} else {
			if len(res) > 1 {
				sort.Slice(res, func(p, q int) bool {
					return l.Precede(res[p], res[q])
				})
			}
			break
		}
	}
	return res[0]
}

// Precede returns the a boolean comparing two elements in partial order which
// is defined in Lattice.
// The result will be true if a precede b, false for otherwise
func (l *Lattice) Precede(a, b string) bool {
	// Precede operation for producted lattice
	if l.isProductValue(a) || l.isProductValue(b) {
		fsta, snda := l.halve(a)
		fstb, sndb := l.halve(b)
		return l.Precede(fsta, fstb) && l.state.Precede(snda, sndb)
	}

	chb := []string{b}   // b and its children

	for {
		if len(chb) == 1 && chb[0] == Bottom {
			return false
		} else if contains(chb, a) {
			return true
		} else {
			chb = l.childrenOf(chb)
		}
	}
}

// Allow returns true when annotation attributes are allowed by policy clause T[c].
func (l *Lattice) Allow(pattrs, aattrs []string) bool {
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

// overlap returns overlaps of policy attributes and annotation attributes (T??? ??? T'??? from paper)
func (l *Lattice) overlap(pattrs, aattrs []string) []string {
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

// Deny returns true when annotation attributes are denied by policy clause T[c] (??? ??? T??? from paper)
func (l *Lattice) Deny(pattrs, aattrs []string) bool {
	overlaps := l.overlap(pattrs, aattrs)
	for _, ol := range overlaps {
		if l.isProductValue(ol) {
			fst, snd := l.halve(ol)
			if (fst == Bottom || snd == Bottom) {
				return false
			}
		} else {
			if ol == Bottom {
				return false
			}
		}
	}
	return true
}

// contains returns a boolean when a slice arr contains a string str
func contains(arr []string, str string) bool {
	for _, e := range arr {
		if e == str {
			return true
		}
	}
	return false
}

func filter(arr []string, fn func(string) bool) []string {
	f := make([]string, 0)
	for _, a := range arr {
		if fn(a) {
			f = append(f, a)
		}
	}
	return f
}



