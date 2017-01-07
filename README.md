# fasthax

This is a beta release. At the moment, it attempts to install `svcBackdoor` to
SVC 0x30 and 0x7b.

# Building

Just run `make` with devkitpro and ctrulib installed. This is a normal homebrew
application that is meant to be launched as a 3dsx.

# For homebrew application developers

User application should not be embedding kernel exploit code to ensure
compatibility for future ARM11 kernel exploits.

ARM11 kernel exploit projects (currently, [waithax][waithax] and this project)
will install backdoor to SVC 0x30, and this SVC already have ACL whether
kernel exploit installation.

So, developers who want to make evevated privileged application can use this
instead of real `svcBackdoor`(SVC 0x7b).

Also, can use this SVC for checking kernel exploit installation, and it make
to avoid system hanging at the using `svcBackdoor` without ACL.

Detail code example, please check [Mrrraou][Mrrraou]'s [snippets][snippets]

[waithax]: https://github.com/Mrrraou/waithax
[hb_menu]: https://github.com/smealum/3ds_hb_menu
[Mrrraou]: https://github.com/Mrrraou
[snippets]: https://gist.github.com/Mrrraou/c74572c04d13c586d363bf64eba0d3a1
