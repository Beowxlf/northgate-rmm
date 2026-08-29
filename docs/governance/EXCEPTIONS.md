# Security Exception Process

An exception record must contain:

- unique ID and affected requirement/check;
- exact file, component, environment, target, and version scope;
- evidence and reason the requirement cannot currently be met;
- threat and impact analysis;
- compensating preventive, detective, and recovery controls;
- owner and independent approver;
- creation and expiry dates;
- remediation issue and milestones;
- closure evidence.

Exceptions cannot authorize secrets in source, disable revocation, convert unknown
results to success, bypass release signatures, or silently broaden target scope.
Critical exceptions close the affected operational gate unless the project owner
documents extraordinary risk acceptance with a fixed short expiry.

No exceptions exist.
