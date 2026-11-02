# SBOM document identity

## What happened
Release packaging passed, but SBOM attestation rejected the generated document.

## Root cause
The attestation format detector requires `serialNumber` alongside `bomFormat`
and `specVersion`. The generator omitted that document identity.

## Rule
Check the attestation consumer contract in the SBOM self-test, including a valid UUID URN.
