#!/bin/bash

env $(grep -v '^#' el_issue.conf | xargs) target/debug/el_issuer
