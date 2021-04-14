package grok

import (
	"errors"
	"fmt"
	"strings"
	"text/scanner"
)

const (
	ALLOW      = true
	DENY       = false
	Allow      = "ALLOW"
	Deny       = "DENY"
	Except     = "EXCEPT"
	lefBrace   = "{"
	rightBrace = "}"
)

// pair is an pair of attribute name and attribute value. exmaple: DataType IPAddrees
type pair struct {
	name  string // attribute name (i.e. lattice)
	value string // attribute value (picked from lattice elements)
}

// Clause is a slice of pairs.
// There may be duplicate attributes in a policy clause, e.g. DataType IPAddress DataType AccountID
type Clause []pair

// ValuesOf returns the attribute values of a Clause when its attribute name is attr
func (c Clause) ValuesOf(attr string) []string {
	values := make([]string, 0)
	for _, p := range c {
		if attr == p.name {
			values = append(values, p.value)
		}
	}
	return values
}

// Annotation is an alias of Clause, which is used as metadata of a program block
type Annotation Clause

// ValuesOf
func (an Annotation) ValuesOf(attr string) []string {
	return Clause(an).ValuesOf(attr)
}

// Policy is composed of its mode, clause, and exceptions. It is based on some lattices.
type Policy struct {
	Mode    bool
	Clause
	Excepts []Policy
	baseOn  map[string]*Lattice
}

// NewPolicy creates a Policy instance based on some lattices.
func NewPolicy(ls []*Lattice) *Policy {
	// checks the dependant lattices that are mandatory for a Policy
	if ls == nil || len(ls) == 0 {
		panic("policy: input lattices should not be empty")
	}
	policy := new(Policy)
	policy.Clause = make([]pair, 0)
	policy.Excepts = make([]Policy, 0)

	policy.baseOn = make(map[string]*Lattice)
	for _, l := range ls {
		policy.baseOn[l.Name] = l
	}

	return policy
}

// ParsePolicy parses a policy string
func (p *Policy) ParsePolicy(pstr string) error {
	var s scanner.Scanner
	s.Init(strings.NewReader(pstr))

	// policy is a nested structure
	tokens := make([]string, 0)
	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		tt := s.TokenText()
		// fmt.Println(tt)
		tokens = append(tokens, tt)
	}

	pp, err := p.parsePolicyTokens(tokens)
	if err != nil {
		return err
	}
	p.Mode = pp.Mode
	p.Clause = pp.Clause
	p.Excepts = pp.Excepts
	return nil
}

// parsePolicyTokens parses a slice of tokens to a Policy
func (p *Policy) parsePolicyTokens(ts []string) (Policy, error) {
	n := len(ts)
	pi := 0
	// the first token must be ALLOW or DENY
	policy := Policy{}
	if Allow == ts[0] || Deny == ts[0] {
		policy.Mode = Allow == ts[0]
		pi = 1
	} else {
		return policy, errors.New("policy: don't start with ALLOW or DENY")
	}

	i := 1
	// The tokens between ALLOW/DENY and EXCEPT are the main content of current policy's clause
	for i < n && Except != ts[i] {
		i++
	}
	tt := ts[pi:i]
	clause, err := p.parseClauseTokens(tt)
	if err != nil {
		return policy, err
	}
	policy.Clause = clause

	// There must be except clauses if i < n
	if i < n {
		if ts[i+1] != lefBrace || ts[n-1] != rightBrace {
			return policy, errors.New("policy: except clause isn't warpped by { and }")
		}
		// the mode of except clauses must be the opposite of policy's main clause
		var mode string
		if policy.Mode {
			mode = Deny
		} else {
			mode = Allow
		}
		pi = i + 2
		if ts[i+2] != mode {
			return policy, errors.New("policy: except clause doesn't have the opposite mode")
		}
		depth := 0
		i = i + 3 // skip the { and mode

		excepts := make([]Policy, 0)
		for i < n-1 {
			if ts[i] == lefBrace {
				depth++
			}
			if ts[i] == rightBrace {
				depth--
			}
			// first condition: for multiple exceptions
			// second condition: for only one exception
			if (depth == 0 && mode == ts[i]) || (i == n-2) {
				if i == n-2 {
					i++
				}
				po, err := p.parsePolicyTokens(ts[pi:i])
				if err != nil {
					return policy, err
				}
				excepts = append(excepts, po)
				pi = i
			}
			i++
		}
		policy.Excepts = excepts
	}

	policy.baseOn = p.baseOn
	return policy, nil
}

// ParseClause returns a Clause instance after parsing a string
func (p *Policy) ParseClause(str string) (Clause, error) {
	var s scanner.Scanner
	s.Init(strings.NewReader(str))

	tokens := make([]string, 0)
	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		tt := s.TokenText()
		tokens = append(tokens, tt)
	}
	if len(tokens) % 2 != 0 {
		return nil, errors.New("policy: clause is not composed of name-value pairs")
	}

	return p.parseClauseTokens(tokens)
}

// ParseAnnotation returns an Annotation instance after parsing a string
func (p *Policy) ParseAnnotation(str string) (Annotation, error) {
	clause, err := p.ParseClause(str)
	if err != nil {
		return nil, err
	}
	return Annotation(clause), nil
}

// parseClauseTokens returns a Clause instance after parsing a slice of tokens
func (p *Policy) parseClauseTokens(ts []string) (Clause, error) {
	var clause Clause = make(Clause, 0)
	
	// current lattice name
	var currLa string
	for _, tt := range ts {
		if "" == currLa {
			la, err := p.LatticeName(tt)
			if err != nil {
				return nil, err
			}
			currLa = la
		} else {
			lv, err := p.LatticeValue(tt, currLa)
			if err != nil {
				return nil , err
			}
			clause = append(clause, pair{currLa, lv})
			currLa = ""
		}
	}
	return clause, nil
}

// ApplyOn decides whether a policy can apply on an annotation
// true means annotation is allowed by the policy
// false means annotation is denied by the policy
// Note: refer to inferences rules in page 7
func (p *Policy) ApplyOn(an Annotation) bool {
	if p.Mode {
		for attr, l := range p.baseOn {
			v := an.ValuesOf(attr)
			if !l.Allow(p.Clause.ValuesOf(attr), v) {
				return false
			}
		}

		for _, ex := range p.Excepts {
			if !(&ex).ApplyOn(an) {
				return false
			}
		}
		return true

	} else {
		for attr, l := range p.baseOn {
			v := an.ValuesOf(attr)
			if !l.Deny(p.Clause.ValuesOf(attr), v) {
				return true
			}
		}
		var overlap Annotation
		for attr, l := range p.baseOn {
			vs := l.overlap(an.ValuesOf(attr), p.Clause.ValuesOf(attr))
			for _, v := range vs {
				overlap = append(overlap, pair{attr, v})
			}
		}
		for _, ex := range p.Excepts {
			if (&ex).ApplyOn(overlap) {
				return true
			}
		}
		return false
	}
}

// LatticeName returns a valid lattice name, or returns error
func (p *Policy) LatticeName(s string) (string, error) {
	for _, l := range p.baseOn {
		if s == l.Name {
			return l.Name, nil
		}
	}
	return "", errors.New(fmt.Sprintf("policy: %s is not a valid lattice name", s))
}

// LatticeValue returns a valid lattice value from its a dependant lattice, or returns error
func (p *Policy) LatticeValue(s string, name string) (string, error) {
	for _, e := range p.baseOn[name].Edges {
		if s == e.From || s == e.To {
			return s, nil
		}
	}
	return "", errors.New(fmt.Sprintf("policy: %s is not a valid value in lattice %s", s, name))
}
