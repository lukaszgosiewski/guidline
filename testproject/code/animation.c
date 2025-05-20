#include <stdio.h>
#include "animation.h"


enum { TABLESIZE = 100 };

static int table[TABLESIZE];

int *f(int index) {
  if (index < TABLESIZE) {
    return table + index;
  }
  return NULL;
}

void displayFrame(int frame) {
    char buffer[50];
    char* frames[] = {
        "  o  \n /|\\ \n / \\ ",
        "  o  \n-/|\\ \n / \\ ",
        "  o  \n /|\\-\n / \\ ",
        "  o  \n /|\\ \n / \\-"
    };
    
    printf(*f(10));

    sprintf(buffer, "%s", frames[frame]);
    printf("%s\n", buffer);
}