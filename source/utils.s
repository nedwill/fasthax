/* MIT License

Copyright (c) 2016 Mrrraou

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
.arm
.section .text


@ TuxSH definitely is the bestest
.global convertVAToPA
.type   convertVAToPA, %function
convertVAToPA:
    mov r1, #0x1000
    sub r1, #1
    and r2, r0, r1
    bic r0, r1
    mcr p15, 0, r0, c7, c8, 0    @ VA to PA translation with privileged read permission check
    mrc p15, 0, r0, c7, c4, 0    @ read PA register
    tst r0, #1                   @ failure bit
    bic r0, r1
    addeq r0, r2
    movne r0, #0
    bx lr


.global flushEntireCaches
.type   flushEntireCaches, %function
flushEntireCaches:
    mov r0, #0
    mcr p15, 0, r0, c7, c10, 0  @ clean entire DCache
    mov r0, #0
    mcr p15, 0, r0, c7, c10, 5
    mcr p15, 0, r0, c7, c5,  0  @ invalidate the entire ICache & branch target cache
    mcr p15, 0, r0, c7, c10, 4  @ data synchronization barrier
    bx lr

