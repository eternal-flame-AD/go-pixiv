package main

import (
	"fmt"
	"strconv"
)

type boolflag struct {
	val *bool
}

func (c boolflag) String() string {
	if c.val == nil {
		return ""
	}
	return strconv.FormatBool(*c.val)
}

func (_ boolflag) IsBoolFlag() bool {
	return true
}

func (c boolflag) Set(s string) error {
	switch s {
	case "no":
	case "false":
	case "yes":
		fallthrough
	case "true":
		fallthrough
	case "":
		*c.val = true
	default:
		return fmt.Errorf("Failed to parse boolflag param %s", s)
	}
	return nil
}

func (c *boolflag) Get() interface{} {
	return *c.val
}
