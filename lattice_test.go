package grok

import (
	"fmt"
	"os"
	"testing"
)

var lattice = NewLattice(
	`{
		"name": "DataType",
		"edges": {
			"UniqueID": ["AccountID", "IPAddress"],
			"Location": ["IPAddress"]
		}
	}`)

func TestNewLattice(t *testing.T) {
	cases := []struct {
		name  string
		value interface{}
		want  interface{}
	}{
		{"name",       lattice.Name,       "DataType"},
		{"len(edges)", len(lattice.Edges), 7},
	}
	for _, c := range cases {
		if c.value != c.want {
			t.Errorf("%q = %q, want %q", c.name, c.value, c.want)
		}
	}
}

func TestNewLattices(t *testing.T) {
	var lattices = NewLattices(
		`[
		{"name": "DataType", "edges": { "Location": ["IPAddress"]}},
		{"name": "Purpose", "edges": { "Sharing": [] } }
	]`)
	cases := []struct {
		name  string
		value interface{}
		want  interface{}
	}{
		{"len(lattices)",          len(lattices),            2},
		{"lattices[0].Name",       (lattices)[0].Name,       "DataType"},
		{"len(lattices[0].Edges)", len((lattices)[0].Edges), 3},

		{"lattices[1].Name",       (lattices)[1].Name,       "Purpose"},
		{"len(lattices[1].Edges)", len((lattices)[1].Edges), 2},
	}
	for _, c := range cases {
		if c.value != c.want {
			t.Errorf("%q = %q, want %q", c.name, c.value, c.want)
		}
	}
}

func TestChildrenOf(t *testing.T) {
	cases := []struct {
		parents  []string
		children []string
	}{
		{[]string{"TOP"},      []string{"Location", "UniqueID"}},
		{[]string{"Location"}, []string{"IPAddress"}},
	}
	for _, c := range cases {
		got := lattice.childrenOf(c.parents)
		if !equals(got, c.children) {
			t.Errorf("childrenOf(%q) = %q, want %q", c.parents, got, c.children)
		}
	}
}

func TestMeet(t *testing.T) {
	cases := []struct {
		a    string
		b    string
		want string
	}{
		{"AccountID", "UniqueID", "AccountID"},
		{"AccountID", "TOP",      "AccountID"},
		{"AccountID", "Location", "BOTTOM"},
	}
	for _, c := range cases {
		got := lattice.Meet(c.a, c.b)
		if got != c.want {
			t.Errorf("Meet(%q, %q) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
}

func TestParentsOf(t *testing.T) {
	cases := []struct {
		parents  []string
		children []string
	}{
		{[]string{"TOP"},                  []string{"Location", "UniqueID"}},
		{[]string{"Location", "UniqueID"}, []string{"IPAddress"}},
	}
	for _, c := range cases {
		got := lattice.parentsOf(c.children)
		if !equals(got, c.parents) {
			t.Errorf("parentsOf(%q) = %q, want %q", c.children, got, c.parents)
		}
	}
}

func TestJoin(t *testing.T) {
	cases := []struct {
		a    string
		b    string
		want string
	}{
		{"AccountID", "UniqueID", "UniqueID"},
		{"AccountID", "TOP",      "TOP"},
		{"AccountID", "Location", "TOP"},
	}
	for _, c := range cases {
		got := lattice.Join(c.a, c.b)
		if got != c.want {
			t.Errorf("Join(%q, %q) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
}

func TestPrecede(t *testing.T) {
	cases := []struct {
		a    string
		b    string
		want bool
	}{
		{"AccountID", "Location", false},
		{"AccountID", "UniqueID", true},
		{"AccountID", "TOP",      true},
	}
	for _, c := range cases {
		got := lattice.Precede(c.a, c.b)
		if got != c.want {
			t.Errorf("Precede(%q, %q) = %t, want %t", c.a, c.b, got, c.want)
		}
	}
}

func TestAllow(t *testing.T) {
	cases := []struct {
		pattrs []string
		aattrs []string
		want   bool
	}{
		{[]string{"IPAddress", "AccountID"}, []string{"IPAddress"}, true},
		{[]string{"IPAddress"},              []string{"TOP"},       false},
	}
	for _, c := range cases {
		got := lattice.Allow(c.pattrs, c.aattrs)
		if got != c.want {
			t.Errorf("Allow(%q, %q) = %t, want %t", c.pattrs, c.aattrs, got, c.want)
		}
	}
}

func TestOverlap(t *testing.T) {
	cases := []struct {
		pattrs []string
		aattrs []string
		want   []string
	}{
		{[]string{"IPAddress", "AccountID"}, []string{"IPAddress"},              []string{"IPAddress", "BOTTOM"}},
		{[]string{"IPAddress", "AccountID"}, []string{"IPAddress", "AccountID"}, []string{"IPAddress", "AccountID"}},
		{[]string{"IPAddress"},              []string{"IPAddress", "AccountID"}, []string{"IPAddress"}},
	}
	for _, c := range cases {
		got := lattice.overlap(c.pattrs, c.aattrs)
		if !equals(got, c.want) {
			t.Errorf("overlap(%q, %q) = %q, want %q", c.pattrs, c.aattrs, got, c.want)
		}
	}
}

func TestDeny(t *testing.T) {
	cases := []struct {
		pattrs []string
		aattrs []string
		want   bool
	}{
		{[]string{"IPAddress", "AccountID"}, []string{"IPAddress"},              false},
		{[]string{"IPAddress", "AccountID"}, []string{"IPAddress", "AccountID"}, true},
	}
	for _, c := range cases {
		got := lattice.Deny(c.pattrs, c.aattrs)
		if got != c.want {
			t.Errorf("Deny(%q, %q) = %t, want %t", c.pattrs, c.aattrs, got, c.want)
		}
	}
}

func TestContains(t *testing.T) {
	cases := []struct {
		arr  []string
		str  string
		want bool
	}{
		{[]string{"Hello", "World"}, "World", true},
		{[]string{"Hello", "World"}, "world", false},
		{[]string{},                 "world", false},
	}
	for _, c := range cases {
		got := contains(c.arr, c.str)
		if got != c.want {
			t.Errorf("contains(%q, %q) == %t, want %t", c.arr, c.str, got, c.want)
		}
	}
}

func equals(a []string, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func setup() {
	fmt.Println("setup")
}

func shutdown() {
	fmt.Println("shutdown")
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}
