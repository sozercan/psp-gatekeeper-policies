package k8spspallowedcapabilities

test_input_container_not_allowed_capabilities_allowed {
    input := { "review": input_review, "parameters": input_parameters_in_list}
    results := violation with input as input
    count(results) == 0
}

input_review = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": input_containers_one
      }
    }
}

input_containers_one = [
{
    "name": "nginx",
    "image": "nginx",
    "securityContext": input_capabilities
}]

input_capabilities = [
{
    "capabilities":
        "add":
          - SYS_TIME
}]


input_parameters_wildcard = {
     "allowedCapabilities": [
         "*"
    ]
}

input_parameters_in_list = {
     "allowedCapabilities": [
         "SYS_TIME",
    ]
}

input_parameters_not_in_list = {
     "allowedCapabilities": [
         "NET_ADMIN",
         "DAC_READ_SEARCH"
    ]
}