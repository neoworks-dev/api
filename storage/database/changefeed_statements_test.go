package database

import "testing"

func TestFeedStatementsBindEveryParameter(t *testing.T) {
	requireAllBound(t, "feed shortcuts", shortcutsToNodeStatement, shortcutParams("node"))
	requireAllBound(t, "feed grant holders", grantHoldersStatement, grantHolderParams([]string{"node"}, []string{"ancestor"}))
}
