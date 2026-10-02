package api

import (
	"crypto/rand"
	"math/big"
	"strconv"
	"strings"
)

var adjectives = []string{
	"Quiet", "Brave", "Calm", "Clever", "Swift", "Gentle", "Bright", "Bold",
	"Silent", "Lucky", "Happy", "Mellow", "Nimble", "Proud", "Steady", "Sunny",
	"Witty", "Cosy", "Daring", "Eager", "Fuzzy", "Golden", "Hidden", "Jolly",
	"Kind", "Lively", "Misty", "Noble", "Plucky", "Rapid", "Shy", "Tidy",
	"Vivid", "Wild", "Zesty", "Amber", "Crimson", "Frosty", "Silver", "Velvet",
}

var animals = []string{
	"Otter", "Fox", "Owl", "Panda", "Falcon", "Badger", "Heron", "Lynx",
	"Koala", "Marten", "Raven", "Seal", "Tiger", "Wolf", "Yak", "Zebra",
	"Beaver", "Bison", "Crane", "Dolphin", "Eagle", "Ferret", "Gecko", "Hare",
	"Ibis", "Jaguar", "Lemur", "Moose", "Newt", "Ocelot", "Puffin", "Quail",
	"Robin", "Sparrow", "Toucan", "Walrus", "Whale", "Wombat", "Mole", "Swan",
}

func pick(list []string) string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
	if err != nil {
		return list[0]
	}
	return list[n.Int64()]
}

func friendlyName(taken map[string]bool) string {
	for i := 0; i < 64; i++ {
		n := pick(adjectives) + " " + pick(animals)
		if !taken[strings.ToLower(n)] {
			return n
		}
	}
	base := pick(adjectives) + " " + pick(animals)
	for i := 2; ; i++ {
		n := base + " " + strconv.Itoa(i)
		if !taken[strings.ToLower(n)] {
			return n
		}
	}
}
