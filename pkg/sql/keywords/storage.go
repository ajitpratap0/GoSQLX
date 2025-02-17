package keywords

import (
	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
)

func (k *Keywords) getStorageKeywords() []Keyword {
	return []Keyword{
		{"CSV", models.TokenTypeKeyword, true, false},
		{"PARQUET", models.TokenTypeKeyword, true, false},
		{"ORC", models.TokenTypeKeyword, true, false},
		{"AVRO", models.TokenTypeKeyword, true, false},
		{"STORAGE", models.TokenTypeKeyword, true, false},
		{"COMPRESSION", models.TokenTypeKeyword, true, false},
		{"LOCATION", models.TokenTypeKeyword, true, false},
		{"BUCKET", models.TokenTypeKeyword, true, false},
		{"CLUSTERED", models.TokenTypeKeyword, true, false},
		{"PARTITIONED", models.TokenTypeKeyword, true, false},
		{"FORMAT", models.TokenTypeKeyword, true, false},
		{"DELIMITED", models.TokenTypeKeyword, true, false},
		{"FIELDS", models.TokenTypeKeyword, true, false},
		{"LINES", models.TokenTypeKeyword, true, false},
		{"STORED", models.TokenTypeKeyword, true, false},
		{"FILEFORMAT", models.TokenTypeKeyword, true, false},
		{"INPUTFORMAT", models.TokenTypeKeyword, true, false},
		{"OUTPUTFORMAT", models.TokenTypeKeyword, true, false},
		{"DIRECTORY", models.TokenTypeKeyword, true, false},
		{"EXTERNAL", models.TokenTypeKeyword, true, false},
		{"TEMPORARY", models.TokenTypeKeyword, true, false},
		{"UNLOGGED", models.TokenTypeKeyword, true, false},
		{"TABLESPACE", models.TokenTypeKeyword, true, false},
		{"LOGGING", models.TokenTypeKeyword, true, false},
		{"NOLOGGING", models.TokenTypeKeyword, true, false},
		{"ARCHIVE", models.TokenTypeKeyword, true, false},
		{"UNARCHIVE", models.TokenTypeKeyword, true, false},
		{"COMPRESS", models.TokenTypeKeyword, true, false},
		{"UNCOMPRESS", models.TokenTypeKeyword, true, false},
	}
}
