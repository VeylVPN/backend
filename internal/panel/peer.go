package panel

var allowHookUID = -1

func peerOverride(uid uint32) bool {
	return allowHookUID >= 0 && uint32(allowHookUID) == uid
}
