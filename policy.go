package grok

import (
	"errors"
	"fmt"
	"strings"
	"text/scanner"
)

type PolicyMode bool

const (
	ALLOW	PolicyMode = true
	DENY	PolicyMode = false
)

func (pm PolicyMode) String() string {
	switch (pm) {
	case ALLOW: return "Allow"
	case DENY:	return "Deny"
	default: panic("invalid policy mode")
	}
}

// pair: exmaple: DataType IPAddrees
type pair struct {
	name 	string 	// attribute name (i.e. lattice)
	value 	string 	// attribute value (picked from lattice elements)
}

// Clause: there may be duplicate attributes in one policy clause
type Clause []pair

func (c Clause) ValuesOf(attr string) []string {
	values := make([]string, 0)
	for _, p := range c {
		if attr == p.name {
			values = append(values, p.value)
		}
	}
	return values
}

// Annotation: an alias for clause, used as metadata in flow node
type Annotation Clause

func (an Annotation) ValuesOf(attr string) []string {
	return Clause(an).ValuesOf(attr)
}


// policy definition based on lattice definitions
type Policy struct {
	Mode 		PolicyMode
	Clause
	Excepts		[]Policy
	baseOn 		map[string]Lattice
}

func (p *Policy) Init(ls *[]Lattice) *Policy {
	p.Clause = make([]pair, 0)
	p.Excepts = make([]Policy, 0)

	p.baseOn = make(map[string]Lattice)
	for _, l := range *ls {
		p.baseOn[l.Name] = l
	}
	return p
}


func (p *Policy) checkBaseOn() {
	if p.baseOn == nil || len(p.baseOn) == 0 {
		fmt.Println("policy has no lattices")
	}
}

// ParsePolicy: parse a policy string
func (p *Policy) ParsePolicy(data string) *Policy {
	p.checkBaseOn()

	var s scanner.Scanner
	s.Init(strings.NewReader(data))

	// policy is a nested structure
	tokens := make([]string, 0)
	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		tt := s.TokenText()
		// fmt.Println(tt)
		tokens = append(tokens, tt)
	}

	pp := p.parsePolicyTokens(tokens)
	p.Mode = pp.Mode
	p.Clause = pp.Clause
	p.Excepts = pp.Excepts
	return p
}

func (p *Policy) parsePolicyTokens(ts []string) Policy {
	policy := new(Policy)
	policy.baseOn = p.baseOn
	policy.Excepts = make([]Policy, 0)

	n := len(ts)
	pi := 0
	if "ALLOW" == ts[0] || "DENY" == ts[0] {
		policy.Mode = "ALLOW" == ts[0]
		pi = 1
	} else {
		fmt.Println("policy clause must start with ALLOW or DENY.")
	}

	i := 1
	for i < n && "EXCEPT" != ts[i] {
		i++
	}
	tt := ts[pi:i]
	policy.Clause = p.parseClauseTokens(tt)

	// there must be except clauses, try to find it/them
	if i < n {
		if ts[i+1] != "{" || ts[n-1] != "}" {
			fmt.Println("The except cluase must be warpped by {}")
		}
		var mode string
		if policy.Mode {
			mode = "DENY"
		} else {
			mode = "ALLOW"
		}
		pi = i + 2
		if ts[i+2] != mode {
			fmt.Println("The except clause should have the opposite mode.")
		}
		depth := 0
		i = i + 3 // skip the { and mode
		for i < n -1 {
			if ts[i] == "{" {
				depth ++
			}
			if ts[i] == "}" {
				depth --
			}
			// first condition: for multiple exceptions
			// second condition: for only one exception
			if (depth == 0 && mode == ts[i]) || (i == n-2) {
				if i == n-2 {
					i++
				}
				policy.Excepts = append(policy.Excepts, p.parsePolicyTokens(ts[pi:i]))
				pi = i
			}

			i++
		}
	}

	return *policy
}


func (p *Policy) ParseClause(str string) Clause {
	p.checkBaseOn()

	var s scanner.Scanner
	s.Init(strings.NewReader(str))
	
	tokens := make([]string, 0)
	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		tt := s.TokenText()
		tokens = append(tokens, tt)
	}
	if len(tokens) % 2 != 0 {
		fmt.Println("clause is composed of name-value pairs.")
	}

	return p.parseClauseTokens(tokens)
}


func (p *Policy) ParseAnnotation(str string) Annotation {
	return Annotation(p.ParseClause(str))
}


func (p *Policy) parseClauseTokens(ts []string) Clause {
	var clause Clause = make(Clause, 0)
	var currLa string
	for _, tt := range ts {
		if "" == currLa {
			la, err := p.LatticeName(tt)
			if err != nil {
				fmt.Println(err)
			}
			currLa = la
			// fmt.Println(la)
		} else {
			lv, err := p.LatticeValue(tt, currLa)
			if err != nil {
				fmt.Println(err)
			}
			// fmt.Printf("[%s = %s]\n", currLa, lv)
			clause = append(clause, pair{currLa, lv})
			currLa = ""
		}
	}
	return clause
}


// ApplyOn: whether a policy can apply on an annotation
// true means annotation is allowed by the policy
// false means annotation is denied by the policy
// note: refer to inferences rules in page 7
func (p *Policy) ApplyOn(an Annotation) bool {
	// 
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


func (p *Policy) LatticeName(s string) (string, error) {
	for _, l := range p.baseOn {
		if s == l.Name {
			return l.Name, nil
		}
	}
	return "", errors.New(fmt.Sprintf("%s is not a valid lattice name", s))
}

func (p *Policy) LatticeValue(s string, name string) (string, error) {
	for _, e := range p.baseOn[name].Edges {
		if s == e.From || s == e.To {
			return s, nil
		}
	}
	return "", errors.New(fmt.Sprintf("%s is not a valid value in lattice %s", s, name))
}


