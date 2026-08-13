# Cybersecurity Assessment Report

## Assessment Information

- **Run ID:** demo-run-001
- **Target(s):** demo-web-app
- **Generated At:** 2026-08-12T13:45:28.419239+00:00

## Executive Summary

Executive summary has not yet been generated.

## Severity Summary

- **Total Findings:** 2
- **Critical:** 0
- **High:** 1
- **Medium:** 1
- **Low:** 0
- **Info:** 0

## Detailed Findings

### 1. Outdated Web Server

- **Severity:** High
- **CVSS Score:** 8.0
- **Affected Component:** Web server
- **Detected By:** vulnerability_scanner
- **Tool:** scanner

**Description**

The target is running an outdated web server version.

**Evidence**

Outdated version detected.

**Recommendation**

Upgrade the web server to a currently supported version.

### 2. Missing Security Header

- **Severity:** Medium
- **CVSS Score:** Not scored
- **Affected Component:** /login
- **Detected By:** web_attack

**Description**

A recommended HTTP security header was not present.

**Evidence**

No additional evidence provided.

**Recommendation**

Configure the required HTTP security header.
