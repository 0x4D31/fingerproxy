# Changelog

## Unreleased
- Fix HTTP/2 PRIORITY frame handling. Now only PRIORITY frames targeting idle streams before the first HEADERS frame are recorded, ensuring stable fingerprints across connection reuse.
