# Jongleur - an HTTP/S request juggler for Docker

This is a front-end for those who run multiple docker containers on a single host but want virtual host-like behaviour.

Other solutions I tried were unsatisfactory, usually because of how DNS resolution was handled (nginx in particular is a real PITA on this topic).

[![API Docs](https://godoc.org/github.com/ilowe/jongleur?status.svg)](https://godoc.org/github.com/ilowe/jongleur)