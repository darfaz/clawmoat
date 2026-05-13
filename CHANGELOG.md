# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-05-12

### Added
- Stable v1 positioning: **the open-source agent firewall**.
- Live monitoring dashboard via `clawmoat watch`.
- MCP config scanning via `clawmoat scan-mcp`.
- Vulnerability-ops exploitability scoring and analysis API.
- Host/runtime protection exports for policy, approval, guardian, and monitoring flows.
- Framework integrations and docs for LangChain, OpenAI Agents, LiteLLM, CrewAI, and OpenClaw.

### Changed
- Homepage, README, and package metadata now align around v1 agent-firewall positioning.
- Package hygiene excludes stale local tarballs, patch scraps, and mutable server key state from npm publishes.

### Fixed
- Full test suite is green under Node's built-in test runner.
- Lint script dependency is declared for release hygiene.

## [0.3.0] - 2025-02-18

### Added
- **Excessive Agency Scanner (ASI02/ASI03)**: Advanced security scanning for AI agent behaviors with comprehensive test coverage
- **OpenClaw Skill Integration**: Security scanning capabilities specifically designed for AI agent sessions
- **CI/CD Workflow**: Automated testing and continuous integration setup
- **SVG Brand Assets**: New logo, mark, and mark-with-moat SVG assets for better branding

### Changed
- **Renamed Pro Skill to Security Kit**: Better reflects the comprehensive security features
- **New Pricing Structure**: 
  - Pro Skill (Security Kit) now available as one-time $29 purchase
  - Shield and Team subscriptions with 30-day trial period
  - 14-day money-back guarantee
- **Improved Documentation**: Enhanced README with better feature descriptions and setup instructions

### Fixed
- Checkout system now points to live Railway URL for better reliability
- Various styling improvements for better user experience

### UI/UX Improvements
- Bigger, transparent SVG logo with left-aligned navigation
- More space between logo and navigation links
- Narrower pill-shaped "Get Access" button
- Enhanced "Join Waitlist" and "Get Started" button styling and functionality

## [0.2.1] - Previous Release
- Initial stable release with core security features