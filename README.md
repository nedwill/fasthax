<div align="center">
  <br />
  <p>
    <img src="https://pbs.twimg.com/media/C1abCKpUoAEhEkW.jpg" />
  </p>
  <br />
</div>

# 

This is an exploit for an ARM11 kernel vulnerability in Nintendo 3DS versions
<= 11.2.

Core 1 (SYSCORE) runs a thread that handles a synchronization event
queue. Objects added to the queue do not have their reference count incremented.
When the thread goes to fetch an object, it locks the scheduler, but this
doesn't prevent a user thread on core 0 from freeing the timer object, thus
leading to a UAF. Because a vtable pointer is located at the free pointer
location, this leads to kernel code execution. Many workarounds are needed for
stability; those are documented as part of the codebase.

This exploit installs `svcBackdoor` at SVC numbers 0x30 and 0x7b.

# Credits
@nedwill: Vulnerability discovery and exploit code for N3DS USA 11.2, fixes to get 100% stability

@d3m3vilurr: Found offsets for all versions of O3DS/N3DS, many bugfixes, ACL patching

@Steveice10: SVC ACL check patch

@kim-yannick: O3DS 11.2 support, rounding error fix

@kade-robertson: Travis support

@de0u: Teaching me how to find this bug

[Luma3DS][Luma3DS]: svcBackdoor implementation bytes

[waithax][waithax]: some snippets related to finding svcBackdoor

If I missed anyone/anything, feel free to ping me.

# Building

Binaries are available on the release page. Otherwise, just run `make` with
devkitpro and ctrulib installed. This is a normal homebrew application that is
meant to be launched as a `.3dsx`.

# For homebrew application developers

User applications should not embed kernel exploit code to ensure compatibility
for future ARM11 kernel exploits, and to allow updates to existing exploits.

All current ARM11 kernel exploit projects (currently, [waithax][waithax]
and this project) install a backdoor to SVC 0x30, as this SVC is originally
stubbed, and always permitted by ACL. This means any process can run code
in the context of the kernel without invasive kernel modifications.

SVC 0x7B is also available as a backdoor for compatibility purposes.

For more detailed code examples, please check [Mrrraou][Mrrraou]'s [snippets][snippets].

[waithax]: https://github.com/Mrrraou/waithax
[Mrrraou]: https://github.com/Mrrraou
[snippets]: https://gist.github.com/Mrrraou/c74572c04d13c586d363bf64eba0d3a1
[Luma3DS]: https://github.com/AuroraWright/Luma3DS
