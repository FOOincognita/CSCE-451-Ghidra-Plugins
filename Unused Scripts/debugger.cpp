#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <iomanip>

#if defined(__i386__)
    const int EIP = 14;
#elif defined(__x86_64__)
    const int RIP = 16;
#endif

typedef char byte_t;

// Debug version of function disassemble
void disassemble(pid_t pid, std::uint32_t addr, std::uint8_t* buf, std::size_t len) {
    std::size_t n = 0;
    while (n < len) {
        // Read the instruction opcode from the buffer
        std::int32_t opcode = *(std::int32_t*)(buf + n);
        // Print the opcode as a hexadecimal value
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (opcode & 0xff) << " ";
        // Move to the next byte in the instruction
        n += 1;
        // Check if the instruction has additional bytes
        if ((opcode & 0xff) == 0x0f) {
            // Read the second opcode byte
            std::int32_t second_opcode = *(std::int32_t*)(buf + n);
            // Print the second opcode byte as a hexadecimal value
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (second_opcode & 0xff) << " ";
            // Move to the next byte in the instruction
            n += 1;
        }
        // Check if the instruction has a ModR/M byte
        if ((opcode & 0xff) == 0x8a || (opcode & 0xff) == 0x8b || (opcode & 0xff) == 0x80 || (opcode & 0xff) == 0x81 || (opcode & 0xff) == 0x83 || (opcode & 0xff) == 0xff) {
            // Read the ModR/M byte
            std::int32_t modrm = *(std::int32_t*)(buf + n);
            // Print the ModR/M byte as a hexadecimal value
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (modrm & 0xff) << " ";
            // Move to the next byte in the instruction
            n += 1;
        }
        // Check if the instruction has an immediate value
        if ((opcode & 0xff) == 0xc2 || (opcode & 0xff) == 0xc3 || (opcode & 0xff) == 0xe8 || (opcode & 0xff) == 0xe9 || (opcode & 0xff) == 0xeb || (opcode & 0xff) == 0xf2 || (opcode & 0xff) == 0xf7 || (opcode & 0xff) == 0xff) {
            // Read the immediate value from the buffer
            std::int32_t immediate = *(std::int32_t*)(buf + n);
            // Move to the next byte in the instruction
            n += 1;
        }
    }
}


/*
// Disassemble function given an address
void disassemble(unsigned char *buf, int len, unsigned int addr) {
    int i;
    for (i = 0; i < len; i += 16) {
        printf("%08x: ", addr + i);
        int j;
        for (j = 0; j < 16 && i + j < len; j++) {
            printf("%02x ", buf[i + j]);
        }
        for (; j < 16; j++) {
            printf("   ");
        }
        printf("  ");
        for (j = 0; j < 16 && i + j < len; j++) {
            printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        }
        printf("\n");
    }
}
*/

void set_breakpoint(pid_t pid, std::uint32_t addr) {
    std::int32_t orig_data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, NULL);
    if (orig_data == -1) {
        std::cerr << "Could not read memory at address " << std::hex << addr << std::endl;
        return;
    }

    std::int32_t new_data = (orig_data & ~0xff) | 0xcc;
    if (ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)new_data) == -1) {
        std::cerr << "Could not set breakpoint at address " << std::hex << addr << std::endl;
        return;
    }

    std::uint32_t saved_eip = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
    if (saved_eip == -1) {
        std::cerr << "Could not read RIP register" << std::endl;
        return;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        std::cerr << "Could not continue child process" << std::endl;
        return;
    }

    std::int32_t status;
    while (true) {
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            std::cout << "Child process exited" << std::endl;
            return;
        } else if (WIFSTOPPED(status)) {
            std::uint32_t stopped_eip = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
            if (stopped_eip == -1) {
                std::cerr << "Could not read RIP register" << std::endl;
                return;
            }

            if (stopped_eip - 1 == addr) {
                // breakpoint hit, restore original instruction
                if (ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)orig_data) == -1) {
                    std::cerr << "Could not restore original instruction" << std::endl;
                    return;
                }

                // set EIP/RIP to the address of the breakpoint
                if (ptrace(PTRACE_POKEUSER, pid, 8 * RIP, (void*)(addr)) == -1) {
                    std::cerr << "Could not set RIP register" << std::endl;
                    return;
                }

                std::cout << "Breakpoint set at address " << std::hex << addr << std::endl;
                return;
            }
        }

        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
            std::cerr << "Could not single-step child process" << std::endl;
            return;
        }
    }
}



// Remove a breakpoint at a given address
bool remove_breakpoint(pid_t pid, std::uint32_t addr, std::uint8_t *saved_data) {
    std::int32_t data = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);
    if (errno != 0) {
        std::cerr << "Could not remove breakpoint: " << strerror(errno) << std::endl;
        return false;
    }

    // Check if the breakpoint is already removed
    if ((std::uint8_t)data != 0xcc) {
        std::cerr << "Breakpoint not found at " << addr << std::endl;
        return false;
    }

    // Restore the original data
    ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)(*saved_data));

    return true;
}

std::int32_t main(std::int32_t argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <program>" << std::endl;
        return 1;
    }

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], argv[1], NULL);
    } else {
        std::int32_t status;
        waitpid(child, &status, 0);

        std::uintptr_t main_addr(0x0);
        FILE* fp = fopen(argv[1], "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, " main(")) {
                    main_addr = (std::uintptr_t)&main;
                    break;
                }
            }
            fclose(fp);
        }
        ptrace(PTRACE_POKETEXT, child, (void*)main_addr, (void*)0xcc);
        while (true) {
            ptrace(PTRACE_CONT, child, NULL, NULL);
            waitpid(child, &status, 0);
            if (WIFEXITED(status)) {
                std::cout << "Child process exited" << std::endl;
                break;
            } else if (WIFSIGNALED(status)) {
                std::cout << "Child process terminated by signal " << WTERMSIG(status) << std::endl;
                break;
            }

            std::uint32_t addr = 0;
            if (WIFSTOPPED(status)) {
                addr = ptrace(PTRACE_PEEKUSER, child, 8 * RIP, NULL);
            }

            std::uint8_t buf[1024];
            std::size_t len = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, buf);
            disassemble(child, addr, buf, len);

            ptrace(PTRACE_POKETEXT, child, (void*)main_addr, (void*)(0x00000000005dc083));
            ptrace(PTRACE_CONT, child, NULL, NULL);
            waitpid(child, &status, 0);
            ptrace(PTRACE_POKETEXT, child, (void*)main_addr, (void*)0xcc);
        }
    }

    return 0;
}
