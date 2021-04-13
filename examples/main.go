package main

import (
	"fmt"
	"github.com/grongjun/grok"
)

func main() {
	// Example in section E "Formal Semantics"
	//
	// Policy:
	// Allows everything except for the use of IPAddress and AccountID in the same program.
	//

	// 1. define a DataType lattice as following structure (part of Fig. 4 (a)).
	//
	//               TOP
	//              /   \
	//       UniqueID  Location
	//           /   \    /
	//  AccountID   IPAddress
	//          \     /
	//          BOTTOM
	//
	dt := grok.NewLattice(`{ "name": "DataType",
		"edges": {
			"UniqueID": ["AccountID", "IPAddress"],
			"Location": ["IPAddress"] }
		}`)
	fmt.Printf("%+v\n", dt)

	ts := grok.NewLattice(`{
		"name": "TypeState",
		"edges": {
			"Encrypted": [],
			"Hashed": [],
			"Truncated": ["Redacted"]
		}
	}`)
	// Product of DataType and TypeState lattice
	dt.Product(ts)

	fmt.Printf("%+v\n", dt)

	// 2. define a policy instance based on above lattice
	//
	// ALLOW DataType TOP EXCEPT { DENY DataType IPAddress DataType AccountID }
	//
	policy := grok.NewPolicy([]*grok.Lattice{dt})
	policy.ParsePolicy(`ALLOW DataType TOP
		EXCEPT { DENY DataType IPAddress DataType AccountID }`)
	fmt.Printf("%+v\n", policy)

	// case 1:
	// a graph node with label "DataType IPAddress", will be allowed by the policy
	r1 := policy.ApplyOn(policy.ParseAnnotation(`DataType IPAddress`))
	fmt.Println(r1) // true

	// case 2
	// a graph node with label "DataType IPAddress DataType AccountID", will be denied by the policy
	r2 := policy.ApplyOn(policy.ParseAnnotation(`DataType IPAddress DataType AccountID`))
	fmt.Println(r2) // false

}
