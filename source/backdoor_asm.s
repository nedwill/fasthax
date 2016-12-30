.arm
.align 4

.section .text.svcMyBackdoor, "ax", %progbits
.global svcMyBackdoor
.type svcMyBackdoor, %function
.align 2
svcMyBackdoor:
	svc 0x2f
	bx  lr

.section .text.svcMyBackdoor2, "ax", %progbits
.global svcMyBackdoor2
.type svcMyBackdoor2, %function
.align 2
svcMyBackdoor2:
    svc 0x30
    bx  lr
