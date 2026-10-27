# format-detection — format policy delta

## ADDED Requirements

### Requirement: The content probe of a plugin the policy turns off does not run

Detection SHALL use every known format's magic and extensions whatever
`ArchiveyConfig.formats` says. In step 6 (content probes), the probe of a plugin format
that the policy does not allow SHALL NOT run, and detection SHALL record the skip as
`TierSkipReason.NOT_ENABLED_BY_POLICY`. Built-in probes SHALL run as they do without a
policy.

#### Scenario: A plugin that is off runs no code

- **WHEN** a plugin with a content probe is registered and a caller opens a file with
  `FormatPolicy(plugins=False)`
- **THEN** the plugin's probe is not called
- **AND** the detection receipt records the content-probe skip as
  `NOT_ENABLED_BY_POLICY`
