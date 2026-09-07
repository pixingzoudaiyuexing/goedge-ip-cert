package challenge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

const tableName = "edgeACMEAuthentications"

type MySQLStore struct {
	db           *sql.DB
	databaseName string
	mu           sync.RWMutex
	checked      bool
}

func NewMySQLStore(db *sql.DB, databaseName string) (*MySQLStore, error) {
	if db == nil || databaseName == "" {
		return nil, errors.New("challenge DB 和数据库名不能为空")
	}
	return &MySQLStore{db: db, databaseName: databaseName}, nil
}

type columnInfo struct {
	name       string
	dataType   string
	columnType string
	nullable   string
	defaultVal sql.NullString
	extra      string
}

func (s *MySQLStore) CheckSchema(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checked {
		return nil
	}
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("challenge DB ping: %w", err)
	}
	var currentDB sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT DATABASE()`).Scan(&currentDB); err != nil {
		return fmt.Errorf("读取当前数据库: %w", err)
	}
	if !currentDB.Valid || currentDB.String != s.databaseName {
		return fmt.Errorf("%w: 当前数据库 %q，期望 %q", ErrSchemaMismatch, currentDB.String, s.databaseName)
	}
	var engine, collation sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT ENGINE, TABLE_COLLATION FROM information_schema.TABLES
		WHERE TABLE_SCHEMA=? AND TABLE_NAME=?`, s.databaseName, tableName).Scan(&engine, &collation); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: 表 %s 不存在", ErrSchemaMismatch, tableName)
		}
		return fmt.Errorf("读取 challenge table metadata: %w", err)
	}
	if !engine.Valid || !strings.EqualFold(engine.String, "InnoDB") || !collation.Valid || !strings.HasPrefix(strings.ToLower(collation.String), "utf8mb4_") {
		return fmt.Errorf("%w: 表必须使用 InnoDB 和 utf8mb4", ErrSchemaMismatch)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE, IS_NULLABLE,
		COLUMN_DEFAULT, EXTRA FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA=? AND TABLE_NAME=? ORDER BY ORDINAL_POSITION`, s.databaseName, tableName)
	if err != nil {
		return fmt.Errorf("读取 challenge columns: %w", err)
	}
	defer rows.Close()
	columns := map[string]columnInfo{}
	for rows.Next() {
		var column columnInfo
		if err := rows.Scan(&column.name, &column.dataType, &column.columnType, &column.nullable, &column.defaultVal, &column.extra); err != nil {
			return fmt.Errorf("解析 challenge column: %w", err)
		}
		columns[column.name] = column
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(columns) != 6 {
		return fmt.Errorf("%w: %s 列数为 %d，期望 6", ErrSchemaMismatch, tableName, len(columns))
	}
	expected := map[string]struct {
		dataType  string
		contains  string
		nullable  string
		extra     string
		maxLength string
		default0  bool
	}{
		"id":        {dataType: "bigint", contains: "unsigned", nullable: "NO", extra: "auto_increment"},
		"taskId":    {dataType: "bigint", contains: "unsigned", nullable: "YES", default0: true},
		"domain":    {dataType: "varchar", nullable: "YES", maxLength: "varchar(255)"},
		"token":     {dataType: "varchar", nullable: "YES", maxLength: "varchar(255)"},
		"key":       {dataType: "varchar", nullable: "YES", maxLength: "varchar(1024)"},
		"createdAt": {dataType: "bigint", contains: "unsigned", nullable: "YES", default0: true},
	}
	for name, want := range expected {
		got, ok := columns[name]
		if !ok || got.dataType != want.dataType || got.nullable != want.nullable {
			return fmt.Errorf("%w: 列 %s 类型或 nullable 不兼容", ErrSchemaMismatch, name)
		}
		if want.contains != "" && !strings.Contains(strings.ToLower(got.columnType), want.contains) {
			return fmt.Errorf("%w: 列 %s 缺少 %s", ErrSchemaMismatch, name, want.contains)
		}
		if want.maxLength != "" && strings.ToLower(got.columnType) != want.maxLength {
			return fmt.Errorf("%w: 列 %s 类型为 %s，期望 %s", ErrSchemaMismatch, name, got.columnType, want.maxLength)
		}
		if want.extra != "" && !strings.Contains(strings.ToLower(got.extra), want.extra) {
			return fmt.Errorf("%w: 列 %s 缺少 %s", ErrSchemaMismatch, name, want.extra)
		}
		if want.default0 && (!got.defaultVal.Valid || got.defaultVal.String != "0") {
			return fmt.Errorf("%w: 列 %s 默认值不是 0", ErrSchemaMismatch, name)
		}
	}
	var primaryID, tokenIndex bool
	indexRows, err := s.db.QueryContext(ctx, `SELECT INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME
		FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=? AND TABLE_NAME=?`, s.databaseName, tableName)
	if err != nil {
		return fmt.Errorf("读取 challenge indexes: %w", err)
	}
	defer indexRows.Close()
	for indexRows.Next() {
		var name, column string
		var nonUnique, sequence int
		if err := indexRows.Scan(&name, &nonUnique, &sequence, &column); err != nil {
			return err
		}
		if name == "PRIMARY" && nonUnique == 0 && sequence == 1 && column == "id" {
			primaryID = true
		}
		if column == "token" && sequence == 1 {
			tokenIndex = true
		}
	}
	if err := indexRows.Err(); err != nil {
		return err
	}
	if !primaryID || !tokenIndex {
		return fmt.Errorf("%w: 缺少 PRIMARY(id) 或 token 索引", ErrSchemaMismatch)
	}
	s.checked = true
	return nil
}

func (s *MySQLStore) Create(ctx context.Context, item Challenge) (Challenge, error) {
	if err := s.requireChecked(); err != nil {
		return Challenge{}, err
	}
	if item.TaskID != 0 || item.Domain == "" || item.Token == "" || item.Key == "" {
		return Challenge{}, errors.New("challenge 必须使用 taskId=0 且 domain/token/key 非空")
	}
	if len(item.Domain) > 255 || len(item.Token) > 255 || len(item.Key) > 1024 {
		return Challenge{}, errors.New("challenge 字段超过 v1.3.9 schema 长度")
	}
	if item.CreatedAt == 0 {
		item.CreatedAt = time.Now().Unix()
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO edgeACMEAuthentications
		(taskId, domain, token, `+"`key`"+`, createdAt) VALUES (?, ?, ?, ?, ?)`,
		item.TaskID, item.Domain, item.Token, item.Key, item.CreatedAt)
	if err != nil {
		return Challenge{}, fmt.Errorf("创建 challenge: %w", err)
	}
	item.ID, err = result.LastInsertId()
	if err != nil || item.ID <= 0 {
		return Challenge{}, fmt.Errorf("读取 challenge row ID: %w", err)
	}
	return item, nil
}

func (s *MySQLStore) Delete(ctx context.Context, item Challenge) error {
	if err := s.requireChecked(); err != nil {
		return err
	}
	if item.ID <= 0 || item.TaskID != 0 || item.Domain == "" || item.Token == "" {
		return errors.New("challenge delete selector 不完整")
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM edgeACMEAuthentications
		WHERE id=? AND taskId=? AND domain=? AND token=? LIMIT 1`, item.ID, item.TaskID, item.Domain, item.Token)
	if err != nil {
		return fmt.Errorf("删除 challenge: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	if count != 1 {
		return fmt.Errorf("%w: challenge delete 影响 %d 行", ErrAmbiguous, count)
	}
	return nil
}

func (s *MySQLStore) FindOwned(ctx context.Context, domain, token string, createdAt int64) ([]Challenge, error) {
	if err := s.requireChecked(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, taskId, domain, token, createdAt
		FROM edgeACMEAuthentications WHERE taskId=0 AND domain=? AND token=? AND createdAt=? ORDER BY id`,
		domain, token, createdAt)
	if err != nil {
		return nil, fmt.Errorf("查找 owned challenge: %w", err)
	}
	defer rows.Close()
	var result []Challenge
	for rows.Next() {
		var item Challenge
		if err := rows.Scan(&item.ID, &item.TaskID, &item.Domain, &item.Token, &item.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *MySQLStore) requireChecked() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.checked {
		return fmt.Errorf("%w: 写入前尚未通过 schema guard", ErrSchemaMismatch)
	}
	return nil
}
