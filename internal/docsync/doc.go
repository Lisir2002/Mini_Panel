// Package docsync holds the checks that keep the prose honest about the code.
//
// README.md and docs/*.md are written as a set of claims, and almost every claim
// carries a `path:line symbol` pointer so a reader can check it with grep. Those
// pointers are the part that rots first: a function moves, the line number in the
// doc stays, and the doc now points somewhere that does not say what it claims.
// Two full sweeps in one week found the same class of defect both times — drifted
// line numbers, a reversed range, and one test name that does not exist in the
// repository at all.
//
// So the direction is reversed, the same way the CLI table works: nobody has to
// remember to fix the docs, and a doc that cites something that is not there
// fails `make test` instead.
package docsync
