package grok

import (
	"testing"
)

var lattices []Lattice = []Lattice{
	NewLattice(`{ "name": "DataType",
		"edges": {
			"UniqueID": ["AccountID", "IPAddress"],
			"Location": ["IPAddress"] }
		}`),
	NewLattice(`{ "name": "Purpose", "edges": { "Sharing": []} }`),
}
var policy = NewPolicy(lattices)

func TestParseClause(t *testing.T) {
	clause := policy.ParseClause(`DataType IPAddress Purpose Sharing`)

	cases := []struct {
		name  string
		value interface{}
		want  interface{}
	}{
		{"len(clause)",     len(clause),     2},
		{"clause[0].name",  clause[0].name,  "DataType"},
		{"clause[0].value", clause[0].value, "IPAddress"},
		{"clause[1].name",  clause[1].name,  "Purpose"},
		{"clause[1].value", clause[1].value, "Sharing"},
	}
	for _, c := range cases {
		if c.want != c.value {
			t.Errorf("%q = %q, want %q", c.name, c.value, c.want)
		}
	}
}

func TestParsePolicy1(t *testing.T) {
	p := policy.ParsePolicy(`DENY DataType IPAddress`)
	cases := []struct {
		name  string
		value interface{}
		want  interface{}
	}{
		{"mode",         p.Mode,         DENY},
		{"len(clause)",  len(p.Clause),  1},
		{"len(excepts)", len(p.Excepts), 0},
	}
	for _, c := range cases {
		if c.want != c.value {
			t.Errorf("%q = %q, want %q", c.name, c.value, c.want)
		}
	}
}

func TestParsePolicy2(t *testing.T) {
	p := policy.ParsePolicy(`ALLOW DataType UniqueID`)
	cases := []struct {
		name  string
		value interface{}
		want  interface{}
	}{
		{"mode",         p.Mode,         ALLOW},
		{"len(clause)",  len(p.Clause),  1},
		{"len(excepts)", len(p.Excepts), 0},
	}
	for _, c := range cases {
		if c.want != c.value {
			t.Errorf("%q = %q, want %q", c.name, c.value, c.want)
		}
	}
}

func TestParsePolicy3(t *testing.T) {
	p := policy.ParsePolicy(`ALLOW DataType UniqueID Purpose Sharing`)
	cases := []struct {
		name  string
		value interface{}
		want  interface{}
	}{
		{"mode",         p.Mode,         ALLOW},
		{"len(clause)",  len(p.Clause),  2},
		{"len(excepts)", len(p.Excepts), 0},
	}
	for _, c := range cases {
		if c.want != c.value {
			t.Errorf("%q = %q, want %q", c.name, c.value, c.want)
		}
	}
}

func TestParsePolicy4(t *testing.T) {
	p := policy.ParsePolicy(`DENY DataType Location EXCEPT { ALLOW DataType IPAddress }`)
	cases := []struct {
		name  string
		value interface{}
		want  interface{}
	}{
		{"mode",         p.Mode,         DENY},
		{"len(clause)",  len(p.Clause),  1},
		{"len(excepts)", len(p.Excepts), 1},

		{"mode(excepts[0])",        p.Excepts[0].Mode,         ALLOW},
		{"len(excepts[0].clause)",  len(p.Excepts[0].Clause),  1},
		{"len(excepts[0].excepts)", len(p.Excepts[0].Excepts), 0},
	}
	for _, c := range cases {
		if c.want != c.value {
			t.Errorf("%q = %q, want %q", c.name, c.value, c.want)
		}
	}
}

func TestParsePolicy5(t *testing.T) {
	p := policy.ParsePolicy(`DENY DataType UniqueID
        EXCEPT {
          ALLOW DataType AccountID DataType Location
          ALLOW DataType AccountID DataType IPAddress
          }`)
	cases := []struct {
		name  string
		value interface{}
		want  interface{}
	}{
		{"mode", p.Mode, DENY},
		{"len(clause)", len(p.Clause), 1},
		{"len(excepts)", len(p.Excepts), 2},

		{"mode(excepts[0])", p.Excepts[0].Mode, ALLOW},
		{"len(excepts[0].clause)", len(p.Excepts[0].Clause), 2},
		{"len(excepts[0].excepts)", len(p.Excepts[0].Excepts), 0},

		{"mode(excepts[1])", p.Excepts[1].Mode, ALLOW},
		{"len(excepts[1].clause)", len(p.Excepts[1].Clause), 2},
		{"len(excepts[1].excepts)", len(p.Excepts[1].Excepts), 0},
	}
	for _, c := range cases {
		if c.want != c.value {
			t.Errorf("%q = %q, want %q", c.name, c.value, c.want)
		}
	}
}

func TestParsePolicy6(t *testing.T) {
	p := policy.ParsePolicy(`DENY DataType UniqueID
        EXCEPT {
          ALLOW DataType AccountID DataType Location EXCEPT {
              DENY DataType Location Purpose Sharing
                EXCEPT {
                  ALLOW DataType IPAddress
                  }
              }
          ALLOW DataType AccountID DataType IPAddress
          }`)
	cases := []struct {
		name  string
		value interface{}
		want  interface{}
	}{
		{"mode", p.Mode, DENY},
		{"len(excepts)", len(p.Excepts), 2},

		{"mode(excepts[0])", p.Excepts[0].Mode, ALLOW},
		{"len(excepts[0].clause)", len(p.Excepts[0].Clause), 2},
		{"len(excepts[0].excepts)", len(p.Excepts[0].Excepts), 1},

		{"mode(excepts[0].excepts[0])", p.Excepts[0].Excepts[0].Mode, DENY},
		{"len(excepts[0].excepts[0].clause)", len(p.Excepts[0].Excepts[0].Clause), 2},
		{"len(excepts[0].excepts[0].excepts)", len(p.Excepts[0].Excepts[0].Excepts), 1},
	}
	for _, c := range cases {
		if c.want != c.value {
			t.Errorf("%q = %q, want %q", c.name, c.value, c.want)
		}
	}
}

func TestApplyOn(t *testing.T) {
	pstr1 := `ALLOW DataType TOP EXCEPT { DENY DataType IPAddress DataType AccountID }`

	cases := []struct {
		pstr    string
		astr    string
		applyOn bool
	}{
		{"DENY DataType IPAddress DataType AccountID", "DataType IPAddress", true},
		{"DENY DataType IPAddress", "DataType IPAddress DataType AccountID", false},
		{pstr1, "DataType IPAddress", true},
		{pstr1, "DataType IPAddress DataType AccountID", false},
	}
	for _, c := range cases {
		p := policy.ParsePolicy(c.pstr)
		an := policy.ParseAnnotation(c.astr)
		if p.ApplyOn(an) != c.applyOn {
			t.Errorf("Apply [%q] on [%q]: %t, want %t", c.pstr, c.astr, !c.applyOn, c.applyOn)
		}
	}
}
