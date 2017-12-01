# Evade-GFW

This is an experiment project that evades Great firewall of china. The basic idea is to first detect how many hops away the firewall is from out IP address. We can do so by increment the packet TTL every round. If we see current TTL not working, aka, we receive a Time Limit Exceeds, then we increment by one. Until we see a Reset packets injected by great firewall.
After knowing how far away is the firewall, we pick a TTL between firewall and targeted server. To evade firewall censorship,we also need to break our request into characters, and send byte by byte.
We send two copies of packets per request with the TTL, and complete the evasion.
