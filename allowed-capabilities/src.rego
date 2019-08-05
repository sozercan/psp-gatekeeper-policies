package k8spspvolumetypes

violation[{"msg": msg, "details": {}}] {
    capabilities := input.review.object.spec.containers[_].capabilities.add
    not input_capabilities_allowed(capabilities)
    msg := sprintf("One of the allowed capabilities %v is not allowed, pod: %v. Allowed capabilities: %v", [volume_fields, input.review.object.metadata.name, input.parameters.volumes])
}

# * may be used to allow all capabilities
input_capabilities_allowed(capabilities) {
    input.parameters.allowedCapabilities[_] == "*"
}

input_capabilities_allowed(capabilities) {
    allowed_set := {x | x = input.parameters.volumes[_]}
    test := volume_fields - allowed_set
    count(test) == 0
}