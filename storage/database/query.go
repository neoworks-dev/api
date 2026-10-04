package database

import (
	"context"

	surrealdb "github.com/surrealdb/surrealdb.go"
)

// queryRows runs a query and flattens the rows of every statement result.
func queryRows[Row any](ctx context.Context, db *surrealdb.DB, query string, params map[string]any) ([]Row, error) {
	results, err := surrealdb.Query[[]Row](ctx, db, query, params)
	if err != nil {
		return nil, err
	}
	rows := []Row{}
	for _, queryResult := range *results {
		rows = append(rows, queryResult.Result...)
	}
	return rows, nil
}

// queryFirst returns the first row of the query, or ErrNotFound when there is none.
func queryFirst[Row any](ctx context.Context, db *surrealdb.DB, query string, params map[string]any) (*Row, error) {
	rows, err := queryRows[Row](ctx, db, query, params)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return &rows[0], nil
}

func queryExec(ctx context.Context, db *surrealdb.DB, query string, params map[string]any) error {
	_, err := surrealdb.Query[[]any](ctx, db, query, params)
	return err
}

// queryReturned runs a transaction that ends in `RETURN value; COMMIT TRANSACTION;`
// and decodes the returned value. The driver reports one result per statement
// including the commit, so the value is the second-to-last result.
func queryReturned[Value any](ctx context.Context, db *surrealdb.DB, query string, params map[string]any) (*Value, error) {
	results, err := surrealdb.Query[Value](ctx, db, query, params)
	if err != nil {
		return nil, err
	}
	if len(*results) < 2 {
		return nil, ErrNotFound
	}
	returned := (*results)[len(*results)-2]
	return &returned.Result, nil
}
