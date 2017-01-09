.arm
.align 4

.section .text.svcDebugBackdoor, "ax", %progbits
.global svcDebugBackdoor
.type svcDebugBackdoor, %function
.align 2
svcDebugBackdoor:
	svc 0x2f
	bx  lr

.section .text.svcGlobalBackdoor, "ax", %progbits
.global svcGlobalBackdoor
.type svcGlobalBackdoor, %function
.align 2
svcGlobalBackdoor:
    svc 0x30
    bx  lr
