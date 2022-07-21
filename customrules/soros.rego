package rules.sfm.required_tags

import data.fugue

__rego__metadoc__ := {

"id": "SFM_003",

"title": "Required tags missing from resources",

"description": "Check all resources for the presence of required tags",

"custom": {

"controls": {

"SFM-POLICY": [

"SFM-POLICY_1.3"

]

},

"rule_remediation_doc": https://www.notion.so/soros/Tagging-standard-ba173796742345c6be6c55aaece9371a (https://www.notion.so/soros/Tagging-standard-ba173796742345c6be6c55aaece9371a) ,

"providers": [

"AWS"

],

"severity": "High"

}

}

resource_type = "MULTIPLE"

scanned_resources := fugue.resource_types()