/**
 * Purpose: Interactive minesweeper helper. This was made for educational purposes
 *          to teach me about reverse engineering, Windows programming, and
 *          Windows processes
 * Date:    July 21 2020
 * Author:  Tom Daniels <github.com/trdan6577>
 */

#include<stdio.h>
#include<windows.h>
#include<tlhelp32.h>

#define FLAG_TILE_FUNCTION     0x374F  // Offset to the function that flags a given tile
#define NUM_MINES_OFFSET       0x5330  // Offset to the position in memory with the number of mines
#define MINEFIELD_OFFSET       0x5340  // Offset to the start of the minefield in memory
#define WIDTH_OFFSET           0x5334  // Offset to the position in memory containing the width of the field
#define HEIGHT_OFFSET          0x5338  // Offset to the position in memory containing the height of the field
#define MINES_REMAINING_OFFSET 0x5194  // Offset to the number of mines left to be found
#define MINEFIELD_SIZE         0x35F   // Size of the minefield in memory
#define BUFF_SIZE              1024    // Size of buffers
#define MINE                   0x80    // A mine in memory
#define REVEALED_TILE          0x40    // A tile that's been clicked on that's not a bomb
#define UNCLICKED_SPACE        0x0F    // An unclicked tile in memory
#define FLAG                   0x0E    // A flag in memory
#define QUESTION_MARK          0x0D    // A question mark in memory
#define EXPLODED_MINE          0xCC    // The mine you clicked on to lose the game
#define WRONG_MINE             0x0B    // You put a flag over something that wasn't a mine
#define REVEALED_MINE          0x0A    // Value of the least significant byte in memory when all mines are revealed
#define SHELLCODE_LENGTH       0x17    // Size of the shellcode
#define SHELLCODE_CALL_OFFSET  0x11    // Offset to the call operand in the shellcode
#define INST_AFTER_CALL_OFFSET 0x15    // Offset to the instruction after the CALL instruction in the shellcode

DWORD GetProcessPID(char* processName);
BYTE* GetModuleBaseAddress(DWORD PID, char* moduleName, size_t lenModuleName);
void PrintMineField(unsigned char* field, DWORD height, DWORD width);
int FlagAllMines(HANDLE hMineSweeper, DWORD baseAddr, DWORD width, DWORD height, unsigned char* mineField, DWORD numMines);
int SetMineMetadata(HANDLE hMineSweeper, DWORD* numMines, DWORD* height, DWORD* width, unsigned char* mineField, DWORD baseAddr);

int debug = 0;

DWORD GetProcessPID(char* processName) {
/**
 * Purpose: Enumerates all processes looking for a process with the specified
 *          name. Returns the process ID of the first matching process
 * @param processName : char* - null term string containing the name of the process to match. Case sensitive
 * @return : DWORD - process ID of the first process with a matching name or 0 if error
 */

    // Initialize the PROCESSENTRY32 structure
    PROCESSENTRY32 processInformation;
    processInformation.dwSize = sizeof(PROCESSENTRY32);  // As per https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32

    if (debug) printf("Searching the process list for process %s via the executable name\n", processName);

    // Get a list of running processes
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("Error calling CreateToolhelp32Snapshot: %d\n", GetLastError());
        return 0;
    }

    // Get the first Process in the list
    if (!Process32First(hProcessSnap, &processInformation)) {
        printf("Error calling Process32first: %d\n", GetLastError());
        CloseHandle(hProcessSnap);
        return 0;
    }

    // Iterate through all Processs in the snapshot, searching for
    // the process by name
    do {
        // If the executable name matches, tell the user we found it and clean up
        if (strncmp(processInformation.szExeFile, processName, 12) == 0) {
            if (debug) printf("Found %s. Process id %d\n", processName, processInformation.th32ProcessID);
            CloseHandle(hProcessSnap);
            return processInformation.th32ProcessID;
        }
    } while (Process32Next(hProcessSnap, &processInformation));

    printf("Unable to find process %s. Is it running?\n", processName);
    CloseHandle(hProcessSnap);

    return 0;
}

BYTE* GetModuleBaseAddress(DWORD PID, char* moduleName, size_t lenModuleName) {
/**
 * Purpose: Gets the base address of a given PID in memory
 * @param PID : DWORD - the ID of the process
 * @param moduleName : char*  - the null terminated name of the module
 * @param lenModuleName : size_t - the length of the moduleName string with the null term
 * @return: BYTE*  - the base address of the process in memory or NULL if error
 */

    // Initialize the MODULEENTRY32 structure
    MODULEENTRY32 moduleInformation;
    moduleInformation.dwSize = sizeof(MODULEENTRY32);

    if (debug) printf("Getting the module %s base address from process ID %d\n", moduleName, PID);

    // Take a snapshot of all modules in the specified process
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, PID);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        printf("Error calling CreateToolhelp32Snapshot: %d\n", GetLastError());
        return NULL;
    }

    // Get the first module in the list
    if (!Module32First(hModuleSnap, &moduleInformation)) {
        printf("Error calling Module32First: %d\n", GetLastError());
        CloseHandle(hModuleSnap);
        return NULL;
    }

    // Iterate through all modules in the snapshot, searching for
    // the specified module
    do {
        if (strncmp(moduleInformation.szModule, moduleName, lenModuleName) == 0) {
            if (debug) printf("Module base address is 0x%08x\n", (DWORD)moduleInformation.modBaseAddr);
            CloseHandle(hModuleSnap);
            return moduleInformation.modBaseAddr;
        }
    } while(Module32Next(hModuleSnap, &moduleInformation));

    printf("Unable to find module %s in process ID %d\n", moduleName, PID);
    return NULL;
}

void PrintMineField(unsigned char* field, DWORD height, DWORD width) {
/**
 * Purpose: Prints out the given minefield. This should be the same minefield
 *          that was read from memory
 * @param field : unsigned char* - the minefield
 * @param height : DWORD - the height of the minefield
 * @param width : DWORD - the width of the minefield
 * @return : void - zip. nada.
 */

    // Each row (width) is 32 bytes so heigh must be *32 to get the proper index
    height = height * 32;
    unsigned char currPos;

    // Print out the legend
    printf("Legend:\n------\nB: Unexploded bomb\n_: Blank clicked tile\n"
           "*: exploded bomb\n?: Question mark\n : (space) Blank unclicked tile\n"
           "F: Flag\nX: Incorrectly placed flag. Only shows up after you lose\n\n   ");

    // Print out the X axis
    for (DWORD x = 1; x <= width; x++) {
        printf(" %2d", x);
    }
    
    // Print out the border
    printf("\n   ");
    for (DWORD x = 1; x <= width; x++) {
        printf("---");
    }
    printf("--\n");

    // Print out the minefield
    for (DWORD y = 32; y <= height; y+=32) {

        // But first print out the Y axis and border
        printf("%2d |", y/32);

        // Print out the specific tile
        for (DWORD x = 1; x <= width; x++) {
            
            currPos = field[x + y];

            // Map out each tile position
            if ((currPos & EXPLODED_MINE) == EXPLODED_MINE) printf(" * ");
            else if ((currPos & MINE) == MINE) {
                if ((currPos & FLAG) == FLAG && !((currPos ^ MINE) > FLAG)) printf(" BF");
                else if ((currPos & QUESTION_MARK) == QUESTION_MARK && !((currPos ^ MINE) > QUESTION_MARK)) printf(" B?");
                else printf(" B ");
            }
            else if ((currPos & REVEALED_TILE) == REVEALED_TILE) {
                if (currPos > REVEALED_TILE) printf(" %d ", currPos ^ REVEALED_TILE);
                else printf(" _ ");
            }
            else if ((currPos & UNCLICKED_SPACE) == UNCLICKED_SPACE) printf("   ");
            else if ((currPos & FLAG) == FLAG) printf("  F");
            else if ((currPos & QUESTION_MARK) == QUESTION_MARK) printf("  ?");
            else if ((currPos & WRONG_MINE) == WRONG_MINE) printf(" X ");
        }

        printf("\n");
    }

    return;
}

int FlagAllMines(HANDLE hMineSweeper, DWORD baseAddr, DWORD width, \
                 DWORD height, unsigned char* mineField, DWORD numMines) {
/**
 * Purpose: Puts a flag over every mine
 * @param hMineSweeper : HANDLE - process handle to minesweeper
 * @param baseAddr : DWORD - the base address of the minesweeper process in memory
 * @param width : DWORD - the width of the minefield
 * @param height : DWORD - the height of the minefield
 * @param mineField : unsigned char* - the minefield in memory
 * @return : int - 0 on success, 1 on failure
 */

    // To pass two or more arguments to CreateRemoteThread, we'll use a struct
    // to put two ints on the stack
    struct parameters_s {
        int x;
        int y;
    };

    // Local variables
    unsigned char buff = (unsigned char)(MINE | UNCLICKED_SPACE);
    struct parameters_s *mineLocations = (struct parameters_s*)malloc(sizeof(struct parameters_s)*numMines);
    DWORD minesFound = 0;         // Number of mines found
    DWORD foundExplodedMine = 0;  // Did we find an exploded mine?
    int errorCode = 0;            // A better name would have been "returnCode"
    SIZE_T bytesWritten;          // Receives the number of bytes WriteProcessMemory wrote
    int currOffset;               // The current mine we're dealing with
    HANDLE hThread;               // Handle to the remote thread created by CreateRemoteThread

    // Our shellcode to call with CreateRemoteThread. Allows us to
    // pass multiple parameters via use of a pointer to a structure
    unsigned char shellcode[] = "\x55\x8B\xEC\x8B\x45\x08\x8B\x48\x04"  // ASM pre-amble, pushing x + y coords on stack
                                "\x51\x8B\x55\x08\x8B\x02\x50\xE8\x00"  // calling the right click function in winmine
                                "\x00\x00\x00\x5D\xC3";                 // poping EBP and returning. Lesson learned here
                                                                        // is that threads don't exit properly if you're
                                                                        // debugging them

    // Iterate through the minefield finding the location of all mines
    for (DWORD y = 32; y <= height*32; y+=32) {
        for (DWORD x = 1; x <= width; x++) {

            // Did we find an exploded mine?
            if ((mineField[x + y] & EXPLODED_MINE) == EXPLODED_MINE) {
                foundExplodedMine = 1;
                break;
            }

            // Did we find a mine?
            if ((mineField[x + y] & MINE) == MINE) {
                mineLocations[minesFound].x = (int)x;
                mineLocations[minesFound].y = (int)y/32;
                minesFound++;
            }
        }

        // Did we find an exploded mine?
        if (foundExplodedMine) { break; }
    }

    // If the game isn't over, flag all the mines
    if (!foundExplodedMine) {

        // Allocate space in the remote process for our shellcode
        LPVOID spaceForShellcode = VirtualAllocEx(hMineSweeper, NULL, SHELLCODE_LENGTH, \
                                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!spaceForShellcode) {
            printf("Error allocating space for the shellcode: %d\n", GetLastError());
            free(mineLocations);
            return 1;
        }

        // Allocate space in the remote process for us to write our arguments to
        LPVOID spaceForParameter = VirtualAllocEx(hMineSweeper, NULL, sizeof(struct parameters_s), \
                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!spaceForParameter) {
            printf("Error allocating space for the shellcode parameters: %d\n", GetLastError());
            free(mineLocations);
            VirtualFreeEx(hMineSweeper, spaceForShellcode, SHELLCODE_LENGTH, MEM_RELEASE);
            return 1;
        }

        // Dynamically calculate the operand for the CALL instruction in the shellcode
        int callOpOffset = ((int)baseAddr + FLAG_TILE_FUNCTION) \
                           - ((int)spaceForShellcode + INST_AFTER_CALL_OFFSET);
        
        // Copy the bytes over to an unsigned char array. No need to reverse the byte
        // ordering as they're already reversed in memory
        memcpy(shellcode + SHELLCODE_CALL_OFFSET, &callOpOffset, sizeof(int));

        // Write the shellcode to memory
        if (!WriteProcessMemory(hMineSweeper, spaceForShellcode, (LPCVOID)shellcode, SHELLCODE_LENGTH, \
                                &bytesWritten)) {
            printf("Error calling WriteProcessMemory: %d\n", GetLastError());
            free(mineLocations);
            VirtualFreeEx(hMineSweeper, spaceForShellcode, SHELLCODE_LENGTH, MEM_RELEASE);
            VirtualFreeEx(hMineSweeper, spaceForParameter, sizeof(struct parameters_s), MEM_RELEASE);
            return 1;
        }

        // For each mine location, mark it as flagged
        for (int i = 0; i < (int)numMines; i++) {

            // Get the location of the mine relative to the start of the mine
            // field in the target process
            currOffset = mineLocations[i].x + mineLocations[i].y*32;

            // First make sure the tile doesn't already have a flag
            if (mineField[currOffset] == (FLAG | MINE)) continue;

            // Change the mine to a blank tile if it's a question mark
            if (mineField[currOffset] == (MINE | QUESTION_MARK)) {
                if (!WriteProcessMemory(hMineSweeper, \
                                       (LPVOID)(baseAddr + MINEFIELD_OFFSET + currOffset), \
                                       (LPCVOID)&buff, 1, &bytesWritten)) {
                    printf("Error calling WriteProcessMemory: %d\n", GetLastError());
                    free(mineLocations);
                    errorCode = 1;
                    break;
                }
            }

            // Call the function in minesweeper to add a flag. Will need to allocate memory in
            // the target process, write a struct containing x, y coord to mem, pass the struct as the param
            if (!WriteProcessMemory(hMineSweeper, spaceForParameter, &(mineLocations[i]), \
                                    sizeof(struct parameters_s), &bytesWritten)) {
                printf("Error calling WriteProcessMemory: %d\n", GetLastError());
                errorCode = 1;
                break;
            }

            // Create the remote thread and wait for it to finish executing.
            // Otherwise, we could overwrite spaceForParameter before the
            // thread gets a chance to use it.
            hThread = CreateRemoteThread(hMineSweeper, NULL, 0, (LPTHREAD_START_ROUTINE)spaceForShellcode,\
                                         spaceForParameter, 0, NULL);
            if (!hThread) {
                printf("Error calling CreateRemoteThread: %d\n", GetLastError());
                errorCode = 1;
                break;
            }
            WaitForSingleObject(hThread, 1000);
            CloseHandle(hThread);
        }
        VirtualFreeEx(hMineSweeper, spaceForShellcode, SHELLCODE_LENGTH, MEM_RELEASE);
        VirtualFreeEx(hMineSweeper, spaceForParameter, sizeof(struct parameters_s), MEM_RELEASE);
    } // END if (!foundExplodedMine)
    else {
        printf("Found an exploded mine. The game is already over. Start a new game first\n");
    }

    // "-STEP ON YOUR RIGHT FOOT- FREE YOUR MEMORY ALLOCATIONS, DON'T FORGET IT"
    //     - Spongebob Squarepants on dynamic memory allocation
    free(mineLocations);

    return errorCode;
}

int SetMineMetadata(HANDLE hMineSweeper, DWORD* numMines, DWORD* height, DWORD* width, \
                    unsigned char* mineField, DWORD baseAddr) {
/**
 * Purpose: Sets information about the current minesweeper game including the
 *          dimensions of the minefield, the minefield itself, and the number of mines
 * @param hMineSweeper : HANDLE - process handle to minesweeper with PROCESS_ALL_ACCESS
 * @param numMines : DWORD* - the total number of mines in the minefield
 * @param height : DWORD* - the height of the minefield
 * @param width : DWORD* - the width of the minefield
 * @param mineField : unsigned char* - the minefield
 * @param baseAddr : DWORD - Base address of the minesweeper module in the minesweeper process
 * @return int - 0 if success, 1 if failure. Otherwise, all data "returned"
 *         is set in the parameter pointers
 */

    // Local Variables
    SIZE_T bytesRead;               // Number of bytes read by ReadProcessMemory
    SIZE_T bytesToRead = 4;         // Number of bytes we want ReadProcessMemory to read
    unsigned int buff;              // Pointer to data read by ReadProcessMemory

    // Getting the number of mines
    if (!ReadProcessMemory(hMineSweeper, (LPCVOID)(baseAddr + NUM_MINES_OFFSET), \
                          (LPVOID)numMines, bytesToRead, &bytesRead)) {
        printf("Error reading the number of mines from memory: %d\n", GetLastError());
        return 1;
    }

    // Get the height of the minefield
    bytesToRead = 1;
    if (!ReadProcessMemory(hMineSweeper, (LPCVOID)(baseAddr + HEIGHT_OFFSET), \
        (LPVOID)&buff, bytesToRead, &bytesRead)) {
        printf("Error reading the height of minefield from memory: %d\n", GetLastError());
        return 1;
    }
    *height = (DWORD)buff;

    // Get the width of the minefield
    if (!ReadProcessMemory(hMineSweeper, (LPCVOID)(baseAddr + WIDTH_OFFSET), \
        (LPVOID)&buff, bytesToRead, &bytesRead)) {
        printf("Error reading the width of minefield from memory: %d\n", GetLastError());
        return 1;
    }
    *width = (DWORD)buff;

    // Read the minefield
    bytesToRead = MINEFIELD_SIZE;
    if (!ReadProcessMemory(hMineSweeper, (LPCVOID)(baseAddr + MINEFIELD_OFFSET), \
        mineField, bytesToRead, &bytesRead)) {
        printf("Error reading the minefield from memory: %d\n", GetLastError());
        return 1;
    }

    return 0;
}

int main(void) {

    // Local variables
    char* mineSweeperName     = "winmine.exe";            // Name of minesweeper exe
    size_t lenMineSweeperName = strlen(mineSweeperName);  // length of exe name
    char input = '0';               // The user's selection
    DWORD MineSweeperPID;           // PID of minesweeper
    DWORD baseAddr;                 // Base address of the minesweeper module in the minesweeper process
    HANDLE hMineSweeper;            // Handle with full permissions to winmine
    unsigned char buff[BUFF_SIZE];  // Pointer to array of minefield data
    DWORD numMines;                 // Number of mines in the minefield
    DWORD height;                   // How high is our minefield?
    DWORD width;                    // The girth of our minefield

    while (input != '5') {

        // Print the menu and get the user's choice
        printf("Menu\n"
            " 1) Print info (minefield sizes, PID, and number of mines)\n"
            " 2) Print minefield\n"
            " 3) Flag all mines\n"
            " 4) Toggle debug messages\n"
            " 5) Exit\n"
            "Select an option: ");
        input = (char)getc(stdin);

        // Not sure the best way to deal with the newline character when getting a char
        while (input == '\n') input = (char)getc(stdin);

        if (input == '1' || input == '2' || input == '3') {
            // Get the PID of the minesweeper process
            MineSweeperPID = GetProcessPID(mineSweeperName);
            if (!MineSweeperPID) continue;

            // Get the base address of the module in memory
            baseAddr = (DWORD)GetModuleBaseAddress(MineSweeperPID, mineSweeperName, lenMineSweeperName);
            if (!baseAddr) continue;

            // Open the process
            hMineSweeper = OpenProcess(PROCESS_ALL_ACCESS, FALSE, MineSweeperPID);
            if (!hMineSweeper) {
                printf("Unable to get a handle to minesweeper using OpenProcess: %d\n", GetLastError());
                return 1;
            }

            // Get metadata about the minefield
            if (SetMineMetadata(hMineSweeper, &numMines, &height, &width, buff, baseAddr)) { continue; }

            // Interpret the input
            switch (input) {
                case '1':  // Print info
                    printf("PID: %d\t\tHeight: %d\t\tWidth: %d\t\tMines: %d\n\n", \
                           MineSweeperPID, height, width, numMines);
                    break;

                case '2':  // Print minefield
                    PrintMineField(buff, height, width);
                    break;

                case '3':  // Flag all mines
                    FlagAllMines(hMineSweeper, baseAddr, width, height, buff, numMines);
            }

            // Clean up
            CloseHandle(hMineSweeper);
        }
        else {
            // Interpret the input
            switch (input) {
                case '4':  // Toggle debug messages
                    if (debug) {
                        printf("Debugging disabled\n");
                        debug = 0;
                    }
                    else {
                        printf("Debugging enabled\n");
                        debug = 1;
                    }

                case '5':  // Exit
                    break;

                default:   // Bad option
                    printf("Invalid option entered.\n\n");
            }
        }
    }  // End interactive while loop

    return 0;
}