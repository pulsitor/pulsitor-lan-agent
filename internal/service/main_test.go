package service

import "flag"

// update rewrites the checked-in packaging files instead of asserting against them.
var update = flag.Bool("update", false, "rewrite the reference files under packaging/")
