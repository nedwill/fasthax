.arm
.align 4

.section .text.svcMyBackdoor, "ax", %progbits
.global svcMyBackdoor
.type svcMyBackdoor, %function
.align 2
svcMyBackdoor:
	svc 0x2f
	bx  lr

.section .text.svcGlobalBackdoor, "ax", %progbits
.global svcGlobalBackdoor
.type svcGlobalBackdoor, %function
.align 2
svcGlobalBackdoor:
    svc 0x30
    bx  lr
