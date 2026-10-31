//go:build !unix

package main

func redrawTerminal()      {}
func setTitle(text string) {}
func pushTitle()           {}
func popTitle()            {}
