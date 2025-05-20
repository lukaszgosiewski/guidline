#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "animation.h"
#include "screen.h"

void print_array(int arr[], size_t size) {
    // Violation: Loop continues past array bounds
    for (size_t i = 0; i <= size; i++) {  // Bug: uses <= instead of 
        printf("Element %zu: %d\n", i, arr[i]);
    }
}

int main() {
    while(1) {
        int numbers[5] = {1, 2, 3, 4, 5};
        print_array(numbers, 5);
        int frame = rand() % 4;
        clearScreen();
        displayFrame(frame);
        usleep(200000);
    }
    return 0;
}