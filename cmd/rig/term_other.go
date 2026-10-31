//go:build !unix

package main

import "syscall"

func detachedProcAttr() *syscall.SysProcAttr { return nil }

func redrawTerminal()      {}
func setTitle(text string) {}
func pushTitle()           {}
func popTitle()            {}
