package keywords

// Keywords is a collection of SQL keywords with efficient lookup
type Keywords struct {
    reservedKeywords map[string]bool
    keywordMap       map[string]Keyword
    dialect         SQLDialect
    ignoreCase      bool
}

// keywordCategory represents different categories of SQL keywords
type keywordCategory string

const (
    categoryBasic      keywordCategory = "basic"
    categoryDML        keywordCategory = "dml"
    categoryDDL        keywordCategory = "ddl"
    categoryFunction   keywordCategory = "function"
    categoryDataType   keywordCategory = "datatype"
    categoryJoin       keywordCategory = "join"
    categoryWindow     keywordCategory = "window"
    categoryAggregate  keywordCategory = "aggregate"
    categoryOperator   keywordCategory = "operator"
    categoryTemporal   keywordCategory = "temporal"
    categoryStorage    keywordCategory = "storage"
    categoryConstraint keywordCategory = "constraint"
    categoryTxn        keywordCategory = "transaction"
    categoryJson       keywordCategory = "json"
    categoryAuth       keywordCategory = "authorization"
    categoryFlow       keywordCategory = "flow_control"
    categoryHA        keywordCategory = "high_availability"
    categoryIdentity   keywordCategory = "identity"
    categoryFormat     keywordCategory = "format"
    categorySchema     keywordCategory = "schema"
    categoryOther      keywordCategory = "other"
)
