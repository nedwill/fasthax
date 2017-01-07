# fasthax

This is a beta release. At the moment, it attempts to install `svcBackdoor` to
SVC 0x30 and 0x7b.

# Building

Just run `make` with devkitpro and ctrulib installed. This is a normal homebrew
application that is meant to be launched as a 3dsx.

# For homebrew application developers

User applications should not embed kernel exploit code to ensure compatibility
for future ARM11 kernel exploits, and to allow updates to existing exploits.

All current ARM11 kernel exploit projects (currently, [waithax][waithax]
and this project) install a backdoor to SVC 0x30, as this SVC is originally
stubbed, and always permitted by ACL. This means any process can run code
in the context of the kernel without invasive kernel modifications.

Because this SVC is permitted, checking whether the backdoor is installed can
be done safely as it will just return an error. Otherwise, the process can fail
when lacking the ACL permission to call `svcBackdoor`.

For more detailed code examples, please check [Mrrraou][Mrrraou]'s [snippets][snippets].

[waithax]: https://github.com/Mrrraou/waithax
[Mrrraou]: https://github.com/Mrrraou
[snippets]: https://gist.github.com/Mrrraou/c74572c04d13c586d363bf64eba0d3a1
