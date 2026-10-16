# Immutable npm range vectors

The 61 synthetic version/range expectations in `vectors.json` were checked
offline against the original public `semver@7.8.5` archive identified in
`provenance.json`. Its SHA-256 is
`d85045d4300d7d57c891336b95df532e73f34c22ffcd222452b6d08b9d127d5d`.
The archive came from the authenticated prepared Pi reference inputs; none of its
bytes were modified. The standalone JSON vectors are public data and can be
explicitly transferred to an independent implementation with their origin and
SHA-256. They create no checkout or executable dependency.

The oracle called `semver.satisfies(vector.version, vector.range)` for each row,
treating invalid range rejection as false. All 61 results matched. The vectors
cover partial major/minor upper boundaries and npm prerelease admission within a
single comparator set, including wildcard, caret, tilde, conjunction and union
forms. `workspace:*` intentionally fails closed. The Python preparation tests
consume only these immutable local data; they do not invoke npm, download an
oracle, or execute Pi. These are semantic conformance cases, not release evidence.
