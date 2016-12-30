# fasthax

# WARNING

This is an *alpha* release. Consider it a PoC that the bug is exploitable,
nothing more. It's not ready to be used by the public, and it's not integrated
with any user-friendly tools. Also, this *won't* let you downgrade or anything
requiring ARM9 access without another bug. This just gives access to all SVCs
on ARM11.

# Info

This is currently an alpha targeted to N3DS 11.2 only.

The bug is present on previous versions (as least as low as 11.0), but the last
jump to a kernel function relies on an 11.2-only offset.

All current offsets, etc. are USA N3DS only, accepting PRs to fix that.

I'm using my own backdoor SVC (0x2f), and this installs another custom backdoor
SVC (0x30). These are normally stubbed, unprivileged SVCs, so that's why I used
them. We'll want to remove any dependency on those SVCs and reinstall a backdoor
to 0x7b and unlock all SVCs to be used by other apps.
