package k8spspallowedcapabilities

violation[{"msg": msg, "details": {}}] {
    container := input_containers[_]
    capabilities := {x | x = container.securityContext.capabilities.add[_]}
    not input_capabilities_allowed(capabilities)
    msg := sprintf("One of the allowed capabilities %v is not allowed, pod: %v. Allowed capabilities: %v", [capabilities, input.review.object.metadata.name, input.parameters.allowedCapabilities])
}

# * may be used to allow all capabilities
input_capabilities_allowed(capabilities) {
    input.parameters.allowedCapabilities[_] == "*"
}

input_capabilities_allowed(capabilities) {
    allowed_set := {x | x = input.parameters.allowedCapabilities[_]}
    test := capabilities - allowed_set
    count(test) == 0
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}
