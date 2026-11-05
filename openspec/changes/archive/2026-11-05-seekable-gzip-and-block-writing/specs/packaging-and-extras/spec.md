# packaging-and-extras — indexed_gzip delta

## MODIFIED Requirements

### Requirement: Optional Extras Enable Specific Formats

The system SHALL provide optional extras that install the third-party libraries needed for
specific formats and capabilities. The `[seekable]` extra MAY include `indexed_gzip` as an
alternative gzip accelerator alongside `rapidgzip` (gzip) and `indexed_bzip2` (bzip2). All
remain optional: the core reads these formats sequentially without them. (No change to the
zero-dependency core: the native blocked-gzip reader adds **no** dependency — it uses stdlib
`zlib`.)

#### Scenario: seekable extra provides the gzip accelerators

- **WHEN** `[seekable]` is installed
- **THEN** `rapidgzip` and/or `indexed_gzip` are available as gzip random-access backends, and `indexed_bzip2` as the bzip2 backend
