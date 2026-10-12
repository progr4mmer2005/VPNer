//go:build !windows

package config

func protect(plain string) (string, error) { return plain, nil }

func unprotect(s string) (string, error) { return s, nil }
