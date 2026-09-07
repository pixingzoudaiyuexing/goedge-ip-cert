package security

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

type SecretRef struct {
	File string `yaml:"file"`
	Env  string `yaml:"env"`
}

func (r SecretRef) Load() (string, error) {
	if (r.File == "") == (r.Env == "") {
		return "", errors.New("secret 必须且只能配置 file 或 env 之一")
	}
	if r.Env != "" {
		value, ok := os.LookupEnv(r.Env)
		if !ok || value == "" {
			return "", fmt.Errorf("环境变量 %q 未设置", r.Env)
		}
		return value, nil
	}
	info, err := os.Lstat(r.File)
	if err != nil {
		return "", fmt.Errorf("读取 secret 文件状态: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("secret 路径不是普通文件")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("secret 文件权限必须为 0600 或更严格，当前为 %04o", info.Mode().Perm())
	}
	data, err := os.ReadFile(r.File)
	if err != nil {
		return "", fmt.Errorf("读取 secret 文件: %w", err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", errors.New("secret 文件为空")
	}
	return value, nil
}
