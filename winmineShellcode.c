#include<stdlib.h>
/**
 * Note that a CALL instruction is: E8 <offset> where <offset> is the number of
 * bytes from 5 + the CALL instruction (CALL is 5 bytes) to the location we're
 * jumping to. In a practical example:
 * 
 * 0x00  ADD EAX, EDX
 * 0x04  INT3
 * 0x08  INT3
 * 0x0C  CALL 0x0
 * 0x11  NOP
 * 
 * The byte code for CALL 0x0 would be E8 FFFFFFEF. 1 byte for E8, 4 bytes for
 * the signed offset.
 */


// To pass two or more arguments to CreateRemoteThread, we'll use a struct
// to put two DWORDs on the stack
struct parameters_s {
    int x;
    int y;
};

void aSecondDeeperTestFunction_oooo_spooky(int x, int y) {
/**
 * Purpose: This is meant to emulate the function I actually
 *          want to call in winmine.exe. It's only in this test
 *          file so I can call a function with similar parameters.
 * @param x : int - the x coord
 * @param y : int - the y coord
 * @return void
 */
    x = x + y; // Make compiler warnings go away
    exit(0);
}

void testFunction(struct parameters_s* param) {
/**
 * Purpose: The meat of the shellcode will be the compiled
 *          result of this function. This is what I will write to memory and
 *          call in CreateRemoteThread.
 * @param param : struct parameters_s* - a pointer to a parameters_s structure
 * @return void
 */
    aSecondDeeperTestFunction_oooo_spooky(param->x, param->y);
    return;
}

    
int main(void) {
    
    struct parameters_s param;
    param.x = 6;
    param.y = 4;

    testFunction(&param);

    return 0;
}