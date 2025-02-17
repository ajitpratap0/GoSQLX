package keywords

import "GoSQLX/pkg/models"

func (k *Keywords) getHAKeywords() []Keyword {
	return []Keyword{
		{"REPLICA", models.TokenTypeKeyword, true, false},
		{"REPLICATION", models.TokenTypeKeyword, true, false},
		{"FAILOVER", models.TokenTypeKeyword, true, false},
		{"SYNC", models.TokenTypeKeyword, true, false},
		{"ASYNC", models.TokenTypeKeyword, true, false},
		{"MASTER", models.TokenTypeKeyword, true, false},
		{"SLAVE", models.TokenTypeKeyword, true, false},
		{"CLUSTER", models.TokenTypeKeyword, true, false},
		{"DISTRIBUTED", models.TokenTypeKeyword, true, false},
		{"STANDBY", models.TokenTypeKeyword, true, false},
		{"MIRROR", models.TokenTypeKeyword, true, false},
	}
}

func (k *Keywords) getReplicationKeywords() []Keyword {
	return []Keyword{
		{"SYNCHRONOUS", models.TokenTypeKeyword, true, false},
		{"ASYNCHRONOUS", models.TokenTypeKeyword, true, false},
		{"QUORUM", models.TokenTypeKeyword, true, false},
		{"CONSENSUS", models.TokenTypeKeyword, true, false},
		{"AVAILABILITY", models.TokenTypeKeyword, true, false},
	}
}
