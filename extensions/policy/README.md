## Overview 
The Policy definition API is an effort to enable granular specification, allowing real governance automation for the software supply chain. This includes coverage of both relatively mundane, complicance-centric concerns (such as proactive license filtering, and vulnerability management), to protection from more esoteric, emerging threats, such as potential malware findings or author-related issues. Finally, this provides some capability to filter package dependencies based on other, more engineering hygiene-centric concerns, such as maintainer responsiveness, etc.

## Structure
Policy definitions are structued via a YAML DSL. This allows the user to define cases which should result in build failures, warnings, information-level log events, and also, specific classes of event to ignore. Below is an outline of the basic policy definition structure - it consists of a name (the top-level keys in the rule definition file), which is expected to have at least a `description` (which may get surfaced to users with the name), which are both essentially free-form text fields. In addition to this, it expects the specification of an `action`, indicating what should _happen_ when the rule is triggered. Finally, one or more filter conditions should be specificied, which indicate how events should be triggered. A very basic example is as follows:

```yaml
rule name:
	description: <description text>
	action: (abort | warn | log | ignore)
	<filter conditions>:
```

The filters also support recursive nesting, which enables more complex combinations of matching parameters to be applied. A more complete example may look like the following:

```YAML
rule name:  
  description: this shows up to users!  
  action: abort  
  any:  
    -      
      issue:  
        tag: HM0012  
    -  
      risks:  
        malware:  
          severity: critical  
          score_threshold: 0.6  
    -  
      health:  
        issue_percent: 0.4  
        pr_percent: 0.5  
    -  
      license:  
        is:  
          - GPL 3.0  
          - GPL 2  
          - LGPL 3.0  
  
another rule:  
  description: another message.  
  action: warn  
  if:  
    any:  
      - 
        issue:  
          severity: critical  
      -  
        issue:  
          severity: high  
    issue:  
      severity: critical  
    license:  
      not:  
        - MIT  
        - BSD  
  
more rules:  
  description: an error occurred.  
  action: ignore  
  all:  
    -      
      issue:  
        tag: A0002
```

This essentially outlines a policy file with three rules, one which would cause a build to break, another which would issue a warning, and a third which would explicitly ignore the presence of an issue. 

### Actions
Currently, the following values are possible selectable `action`s:
* `abort` - If this is specified, an analysis failure message (and negative exit code) will be returned from the product. Essentially, this is equivalent to "fail build".
* `warn` - Emit a warning if the conditions defined are met, but allow the build to proceed. 
* `log` - Log the event, but otherwise allow the build to proceed. Note: This is currently equivalent to `warn`, but in future Phylum releases, will enable logging findings back to the UI or other platforms without breaking the build.
* `ignore` - Explicitly ignore the specified condition.

### Filter Conditions
Digging in a bit further, the following filter conditions are possible, each with their own expected structure:

#### - if:
Expects a dictionary of values to follow; may be any of the other available filter conditions (up to one of each). Any condition that is met will cause this condition to be met (and subsequently, the specified `action` to occur). Example:

```YAML
example if rule:
	description: this shows how if clauses work.
	action: warn
	if:
		risks:
			vulnerability: high
		issue:
			severity: medium
```

This condition would trigger (and issue a warning) if any packages contain either an issue of _any kind_ with a `medium` severity, _or_ if any contain a `vulnerability` that is of `high` severity.

#### - any:
Expects a list of values, and as with the `if` clause, will trigger the action to occur if _any_ of the provided filters match. Example:

```YAML
example any rule:
	description: the any filter in action.
	action: abort
	any:
		-
			issue:
				severity: medium
		-
			issue:
				severity: high
		-
			issue:
				severity: critical
```

This rule would trigger on encountering _any issue_ with a `severity` of either `medium`, `high`, or `critical`, resulting in a broken build. Essentially, this would mean that any issues of `medium` severity or greater would be disallowed from here forward.

#### - all:
As with the `any` filter type, expects a list of values. This condition will only trigger however, if _all_ provided subfilters match. Example:

```YAML
example all rule:
	description: see the all filter at work.
	action: abort
	all:
		-
			issue:
				severity: medium
		-
			issue:
				tag: HM0012
```

This example rule will cause the build to fail if both a medium-severity issue, and the _exact_ issue `HM0012` are present in the package list.

#### - issue:
Filter based on issue-specific attributes, regardless of which domain they fall under. There are two possible criteria that may be provided here for matching:
* `tag` - Each issue type has a unique identifier, or `tag`. This will allow the assignment of special treatment to specific issues among those surfaced in a scan. 
* `severity` - Enables filtering based on issue severity - allowable values are `low`, `medium`, `high`, or `critical`.

Example:

```YAML
example issue rule:
	description: Match some issues.
	action: ignore
	issue:
		tag: HM0012
		severity: low
```

In this case, we will _explicitly ignore_ instances of issue `HM0012` when found, and also any low-severity issues.

#### - risks:
This clause enables more granular, per-domain issue filtering. This allows one entry per risk domain. As with issues, a `tag` may be specified (though those are considered to be globally unique, so this is effectively the same as utilizing `issue: {tag: XXXX}`), in addition  to a `score_threshold` or `severity`. 

##### Allowable Domains:
* `malware`
* `engineering`
* `license`
* `author`
* `vulnerability`

##### Per-Domain Filters:
* `tag` - As with `issue` definition, this is a string value indicating a unique issue identifier. Note that if you specify the `tag` value of an issue outside of the specified domain, it will be functionally impossible for a match to occur.
* `severity` - As with `issue`, the allowable values are: `low`, `medium`, `high`, `critical`, but will only match on issues within the specified domain.
* `score_threshold` - if the package score falls below the specified threshold in the given domain, then this condition will trigger.

For example:
```YAML
rule for risks:
	description: Risks in action.
	action: warn
	risks:
		malware:
			severity: critical
			score_threshold: 0.8
```

would generate a warning for any `critical`-severity malware (i.e., malicious code domain) finding, or in situations where the package's malicious code domain score is below 0.8.

#### - license:
Enables users to explicitly permit or deny specific licenses. Note that this set of values is compared via _explicit match_, and should be a value from the SPDX identifier list (https://spdx.org/licenses/). Note that there will be an issue in the near future to flag non-SPDX licenses, if there is a need to filter for additional, unsupported values.

The `license` key supports essentially two sub-clauses: `is` or `not`. Both of these expect a list of license identifiers to follow - if the `is` clause is provided, for example, the rule will trigger if any of the license identifiers provided are present in the list of the packages. Conversely, if `not` is specified, the rule will trigger if any license in the provided packages is not contained within the provided list. As a more concrete example:
```YAML
license rule one:
	description: explicit deny in action!
	action: abort
	license:
		is:
			- AGPL-1.0-only
			- AGLP-1.0-or-later
			- AGPL-3.0-only
			- AGPL-3.0-or-later

license rule two:
	description: implicit deny in action.
	action: warn
	license:
		not: 
			- BSD-3-Clause
			- MIT
			- Apache-2.0

```

The combination of these rules will cause the build to break if any AGPL variant license is present, and will issue a warning if the license is not BSD-3-Clause, MIT, or Apache 2.0.

#### - author:
Not yet implemented - but coming soon!

#### - health:
Not yet implemented - but coming soon!
