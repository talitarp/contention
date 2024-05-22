## Roadmap for contention Napp

- Write the blueprint
- Specify the openapi.yml and change the validation approach to use openapi standard validation
- Add more matching fields, for instance: ipv4 source and destination, ipv6 source and destination, ip protocol, tcp/udp source/destination port, etc (OK)
- Provide means to list active blocking rules (OK)
- When creating a blocking rule, we should assign a unique identifier for that rule (the identifier will be used later to remove the blocking or eventually modify it) (OK)
- Provide means to asssociate the Block Rule ID to the Flow Cookie ID
- Each Blocking rule should be associated with a Owner
  - Listing the Blocking Rules should also allow filtering by owner
  - Deleting Block Rules should only be allowed from the same owner (??) -- authorization / hierarchy
- Provide means to delete a blocking rule (OK)
- Provide means to specify the duration of a blocking rule
- Make sure user requests are persistent
- Write unit tests
