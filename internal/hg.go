/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cs

import "math/big"

func CommitteeSize(totalNodeCount int64, failedTotalNodesPercentage int64, failureChance big.Rat) int {
	if totalNodeCount < 4 {
		return int(totalNodeCount)
	}
	byzantineRatio, _ := big.NewRat(failedTotalNodesPercentage, 100).Float64()
	for committeeSize := int64(4); committeeSize <= totalNodeCount; committeeSize++ {
		p := hyperGeomRangeSum(totalNodeCount, committeeSize, byzantineRatio)
		if failureChance.Cmp(p) > 0 {
			return int(committeeSize)
		}
	}

	return int(totalNodeCount)
}

func hyperGeomRangeSum(N, n int64, byzantine float64) *big.Rat {
	third := n / 3
	sum := big.NewRat(0, 1)
	for t := int64(0); t <= third; t++ {
		hg := hyperGeom(N, n, t, byzantine)
		sum.Add(sum, hg)
	}
	return sum
}

func hyperGeom(total, committeeTotal, committeeByzantine int64, byzantineRatio float64) *big.Rat {
	byzantineTotal := int64(float64(total) * byzantineRatio)
	a := choose(byzantineTotal, committeeByzantine)
	b := choose(total-byzantineTotal, committeeTotal-committeeByzantine)
	c := choose(total, committeeTotal)

	ar := bigToRat(a)
	br := bigToRat(b)
	cr := bigToRat(c)

	abr := big.NewRat(1, 2).Mul(ar, br)   // a*b
	crInverse := big.NewRat(1, 2).Inv(cr) // 1/c

	return big.NewRat(1, 2).Mul(abr, crInverse) // (a*b)/c
}

func bigToRat(n *big.Int) *big.Rat {
	r, ok := big.NewRat(1, 2).SetString(n.String())
	if !ok {
		panic("failed")
	}
	return r
}

func choose(n, k int64) *big.Int {
	return big.NewInt(0).Binomial(n, k)
}
